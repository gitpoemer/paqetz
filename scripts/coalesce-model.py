#!/usr/bin/env python3
"""How long a coalescing run survives on a channel that loses packets.

Step 3 of the measurement plan in `docs/decisions/D15-tun-offloads.md`.

`tun_ceiling` measures what a virtio-net header is worth once you have a
superpacket to write, and it is several times cheaper per packet to write forty
at a time than one at a time. What it cannot measure is whether paqetz can
*build* those superpackets on the inbound side, because that means coalescing
decrypted packets the way GRO does -- same flow, consecutive sequence numbers --
across a carrier that loses packets and never retransmits. Every gap forces a
flush, and a flush is a short superpacket.

Two things bound a run, and loss is only one of them:

  * **Loss.** A gap in a flow's sequence space ends the run, and nothing will
    ever fill it, so waiting is not an option.
  * **Flow concurrency.** A reader that coalesces only within one batch from
    the wire can merge at most the packets of one flow inside that batch. With
    eight flows interleaved in a batch of thirty-two, the longest possible run
    is four, whatever the loss rate. Holding state across batches lifts that,
    at the cost of latency and memory.

Feed it a capture of real inner traffic, which is the evidence that counts:

    sudo tcpdump -i paqetz0 -s 60 -c 200000 -w inner.pcap   # on either end
    ./scripts/coalesce-model.py inner.pcap --loss 0 0.5 2

`-s 60` keeps only the headers, which is all this reads, and turns a capture
that would be hundreds of megabytes into about fifteen.

Or model it, to see the shape before capturing anything:

    ./scripts/coalesce-model.py --synthetic --flows 1 4 8 32 --loss 0 0.5 2
"""

import argparse
import random
import struct
import sys

# From `sys::BATCH`: the most the inbound thread takes from the wire in one
# syscall, and therefore the most a within-batch coalescer can ever see at once.
BATCH = 32
# A superpacket is capped by what the virtio header can describe and by what the
# far side will accept: 64 KiB, which at a 1448-byte segment is 45.
MAX_SEGMENTS = 45
MAX_BYTES = 65535

# Run lengths are a property of the traffic and say nothing about the machine.
# Turning one into a cost does, so the two figures that takes are supplied
# rather than baked in: run `tun_ceiling plain` and `tun_ceiling uso` on the
# host in question and pass what they report. Without them this reports run
# lengths and writes per packet, which is most of the answer.
BATCHED_AT = 40  # what `tun_ceiling uso` puts in one write


def cost_model(one: float, many: float):
    """Splits two measured points into a per-write overhead and a per-packet copy.

    `cost = copy + overhead / run`, so a write that carries `BATCHED_AT`
    packets divides the overhead that many ways and the copy not at all.
    """
    overhead = (one - many) / (1 - 1 / BATCHED_AT)
    return one - overhead, overhead


def read_pcap(path):
    """Every TCP/UDP packet in `path`, as (flow, seq, wire, payload, ends_run).

    Read once into a list rather than streamed, because the model runs over the
    same packets for each loss rate and each scope, and a capture worth
    measuring is large enough that reading it six times is noticeable.
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError as e:
        sys.exit(f"{path}: {e.strerror}")
    if len(blob) < 24:
        sys.exit(f"{path}: too short to be a pcap")
    magic = struct.unpack("<I", blob[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        end = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        end = ">"
    else:
        sys.exit(f"{path}: not a pcap (magic {magic:#x}); pcapng is not read here")
    link = struct.unpack(end + "I", blob[20:24])[0]
    # 1 Ethernet, 101 raw IPv4, 12/14 raw. A TUN capture is usually raw.
    offset = {1: 14, 101: 0, 12: 0, 14: 0, 113: 16}.get(link)
    if offset is None:
        sys.exit(f"{path}: link type {link} not handled")

    packets = []
    at = 24
    while at + 16 <= len(blob):
        _, _, caplen, _ = struct.unpack(end + "IIII", blob[at : at + 16])
        at += 16
        frame = blob[at : at + caplen]
        at += caplen
        ip = frame[offset:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        proto = ip[9]
        total = struct.unpack("!H", ip[2:4])[0]
        if proto not in (6, 17) or len(ip) < ihl + 8:
            continue
        sport, dport = struct.unpack("!HH", ip[ihl : ihl + 4])
        key = (ip[12:16], ip[16:20], proto, sport, dport)
        if proto == 6:
            seq = struct.unpack("!I", ip[ihl + 4 : ihl + 8])[0]
            flags = ip[ihl + 13] if len(ip) > ihl + 13 else 0
            # GRO flushes on anything that is not plain data.
            ends = bool(flags & 0x07)  # FIN, SYN, RST
            payload = max(total - ihl - ((ip[ihl + 12] >> 4) * 4), 0)
        else:
            seq = None
            ends = False
            payload = max(total - ihl - 8, 0)
        packets.append((key, seq, total, payload, ends))
    if not packets:
        sys.exit(f"{path}: no TCP or UDP packets in it")
    return packets


def synthetic(flows, packets, mss=1448):
    """Interleaved flows, each a continuous TCP stream."""
    seqs = {f: 1 for f in range(flows)}
    for i in range(packets):
        f = i % flows
        seq = seqs[f]
        seqs[f] += mss
        yield (f,), seq, mss + 40, mss, False


def runs(stream, loss, held, rng):
    """Run lengths a coalescer would achieve over `stream`.

    `held` keeps per-flow state across batches, as GRO does. Without it a run
    cannot outlive the batch it started in, which is what the datapath's
    `recvmmsg` hands over.
    """
    open_runs = {}
    finished = []
    seen_in_batch = 0

    def flush(key):
        if key in open_runs:
            finished.append(open_runs.pop(key)[0])

    for key, seq, wire, payload, ends in stream:
        if loss and rng.random() < loss:
            # Lost on the carrier. The flow's sequence space now has a hole
            # nothing will fill, so whatever was accumulating ends here.
            flush(key)
            continue
        seen_in_batch += 1
        if seen_in_batch > BATCH:
            if not held:
                for k in list(open_runs):
                    flush(k)
            seen_in_batch = 1

        count, next_seq, bytes_so_far = open_runs.get(key, (0, None, 0))
        contiguous = next_seq is None or seq is None or seq == next_seq
        if (
            not contiguous
            or count >= MAX_SEGMENTS
            or bytes_so_far + wire > MAX_BYTES
        ):
            flush(key)
            count, bytes_so_far = 0, 0
        count += 1
        bytes_so_far += wire
        open_runs[key] = (
            count,
            None if seq is None else seq + payload,
            bytes_so_far,
        )
        if ends:
            flush(key)

    finished.extend(c for c, _, _ in open_runs.values())
    return finished


def report(label, lengths, model):
    if not lengths:
        print(f"  {label:<22} no runs")
        return
    lengths.sort()
    mean = sum(lengths) / len(lengths)
    packets = sum(lengths)
    cost = ""
    if model:
        copy, overhead = model
        cost = f"   {copy + overhead / max(mean, 1.0):.2f} us/pkt"
    # The figure that matters without a cost model: writes per packet, which
    # the saving is proportional to.
    print(
        f"  {label:<22} mean run {mean:5.1f}   median {lengths[len(lengths) // 2]:3d}"
        f"   writes/pkt {len(lengths) / packets:.3f}{cost}"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?", help="a capture of inner traffic")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--flows", type=int, nargs="+", default=[1, 4, 8, 32])
    ap.add_argument("--loss", type=float, nargs="+", default=[0, 0.5, 2])
    ap.add_argument("--packets", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument(
        "--cost",
        type=float,
        nargs=2,
        metavar=("ONE", "MANY"),
        help="microseconds per packet from `tun_ceiling plain` and `tun_ceiling uso`, "
        "measured on the host in question, which turns run lengths into a predicted cost",
    )
    args = ap.parse_args()
    if not args.pcap and not args.synthetic:
        ap.error("give a pcap, or --synthetic")

    # Before anything is printed, so a missing or unreadable capture is one line
    # rather than a header followed by an error.
    captured = read_pcap(args.pcap) if args.pcap else None

    model = cost_model(*args.cost) if args.cost else None

    print()
    if model:
        copy, overhead = model
        print(f"cost model: {copy:.3f} us per packet + {overhead:.3f} us per write")
        print("            (from the two figures you passed)")
    else:
        print("no cost model: pass --cost ONE MANY from `tun_ceiling` on the host")
        print("               in question to turn run lengths into microseconds")
    print(f"batch {BATCH} from the wire, at most {MAX_SEGMENTS} segments per superpacket")
    print()

    if captured:
        print(f"{len(captured)} packets from {args.pcap}")

    for held in (False, True):
        kind = "held across batches" if held else "within one batch only"
        print(f"==> {kind}")
        for loss in args.loss:
            if captured:
                rng = random.Random(args.seed)
                report(f"{loss}% loss", runs(captured, loss / 100.0, held, rng), model)
            else:
                for flows in args.flows:
                    rng = random.Random(args.seed)
                    stream = synthetic(flows, args.packets)
                    report(
                        f"{flows} flow(s), {loss}% loss",
                        runs(stream, loss / 100.0, held, rng),
                        model,
                    )
        print()

    print("Reading this: writes/pkt is what the saving is proportional to, and")
    print("is a property of the traffic rather than of any machine. A mean run")
    print("under about four is not worth building for.")


if __name__ == "__main__":
    main()
