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

    tcpdump -i paqetz0 -c 200000 -w inner.pcap      # on either end
    ./scripts/coalesce-model.py inner.pcap --loss 0 0.5 2

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

# Fitted to the two points `tun_ceiling` measured, as cost = copy + overhead/run:
#   two measured points, supplied rather than baked in
# which gives a per-write overhead that batching divides, and a per-byte copy
# that it does not.
# Supplied via --cost rather than baked in, because they describe a machine.
OVERHEAD_US = 0.0
COPY_US = 0.0


def predicted_us(run: float) -> float:
    """CPU per packet at a mean run length of `run`."""
    return COPY_US + OVERHEAD_US / max(run, 1.0)


def read_pcap(path):
    """Yields (flow_key, seq, length, ends_run) for each TCP/UDP packet."""
    with open(path, "rb") as fh:
        blob = fh.read()
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
        yield key, seq, total, payload, ends


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


def report(label, lengths):
    if not lengths:
        print(f"  {label:<22} no runs")
        return
    lengths.sort()
    mean = sum(lengths) / len(lengths)
    packets = sum(lengths)
    # The figure that matters: writes per packet, and what that costs.
    print(
        f"  {label:<22} mean run {mean:5.1f}   median {lengths[len(lengths) // 2]:3d}"
        f"   writes/pkt {len(lengths) / packets:.3f}"
        f"   {predicted_us(mean):.2f} us/pkt"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", nargs="?", help="a capture of inner traffic")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--flows", type=int, nargs="+", default=[1, 4, 8, 32])
    ap.add_argument("--loss", type=float, nargs="+", default=[0, 0.5, 2])
    ap.add_argument("--packets", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    if not args.pcap and not args.synthetic:
        ap.error("give a pcap, or --synthetic")

    print()
    print(f"cost model: {COPY_US:.3f} us per packet + {OVERHEAD_US:.3f} us per write")
    print("            (from the two figures you passed)")
    print(f"batch {BATCH} from the wire, at most {MAX_SEGMENTS} segments per superpacket")
    print()

    for held in (False, True):
        kind = "held across batches" if held else "within one batch only"
        print(f"==> {kind}")
        for loss in args.loss:
            if args.pcap:
                rng = random.Random(args.seed)
                stream = read_pcap(args.pcap)
                report(f"{loss}% loss", runs(stream, loss / 100.0, held, rng))
            else:
                for flows in args.flows:
                    rng = random.Random(args.seed)
                    stream = synthetic(flows, args.packets)
                    report(
                        f"{flows} flow(s), {loss}% loss",
                        runs(stream, loss / 100.0, held, rng),
                    )
        print()

    print("Reading this: writes/pkt is what the saving is proportional to, and")
    print("is a property of the traffic rather than of any machine. A mean run")
    print("under about four is not worth building for.")


if __name__ == "__main__":
    main()
