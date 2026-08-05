//! Measuring what a tunnel feels like, rather than whether it is up.
//!
//! `doctor` answers "will this work". This answers "how well", which is a
//! different question and the one that matters once a tunnel is running. Both
//! failures worth catching here are invisible to a throughput test:
//!
//! **Latency under load.** A tunnel that moves 30 Mbit/s while adding a second
//! of delay is a tunnel nobody enjoys using. Deep buffers hide congestion by
//! turning it into delay, so the number to watch is not how fast a transfer
//! completes but how far round-trip time moves while it does. A few
//! milliseconds is a clean path; hundreds is a queue, and whether that queue is
//! ours or the network's is the next question.
//!
//! **A path gone cold.** A tunnel that has been silent lets whatever tracks it
//! forget: the first packets after a pause are lost waking it up, and everything
//! after them is fine. That is invisible to any measurement that warms the path
//! before timing it — which is most of them, including a plain `ping`, if you
//! only look at the second run. So the idle case is measured twice, and the two
//! are compared.
//!
//! Everything is done with `ping`, which is on any host that would run this, so
//! there is nothing to install and every command it runs can be read before it
//! runs.

use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How many probes each measurement sends.
const IDLE_COUNT: u32 = 30;
/// How many probes the loaded measurement sends.
const LOADED_COUNT: u32 = 60;
/// Seconds between probes. Five a second is enough to see a queue fill.
const INTERVAL: &str = "0.2";

/// What one run of probes came back with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Sample {
    /// Percentage of probes that never returned.
    pub(crate) loss: f64,
    /// Fastest round trip, in milliseconds.
    pub(crate) min: f64,
    /// Mean round trip.
    pub(crate) avg: f64,
    /// Slowest round trip.
    pub(crate) max: f64,
    /// Mean deviation, which is what jitter looks like in `ping`'s summary.
    pub(crate) mdev: f64,
}

/// Reads the two summary lines `ping` prints when it finishes.
///
/// Parsed rather than computed, because `ping` has been getting this right for
/// thirty years and a reimplementation would only be a second thing to be wrong.
pub(crate) fn parse(output: &str) -> Option<Sample> {
    let loss = output
        .lines()
        .find(|l| l.contains("packet loss"))?
        .split(',')
        .find(|f| f.contains("packet loss"))?
        .trim()
        .split('%')
        .next()?
        .parse()
        .ok()?;

    let stats = output
        .lines()
        .find(|l| l.contains("rtt ") || l.contains("round-trip"))?;
    let numbers = stats.split('=').nth(1)?;
    let mut parts = numbers.split('/').map(|p| {
        p.trim()
            .trim_end_matches(" ms")
            .trim()
            .parse::<f64>()
            .unwrap_or(f64::NAN)
    });
    Some(Sample {
        loss,
        min: parts.next()?,
        avg: parts.next()?,
        max: parts.next()?,
        mdev: parts.next().unwrap_or(f64::NAN),
    })
}

/// Sends `count` probes and reads the summary.
fn probe(target: &str, count: u32) -> Result<Sample, Box<dyn std::error::Error>> {
    let out = Command::new("ping")
        .args(["-c", &count.to_string(), "-i", INTERVAL, target])
        .output()?;
    // A run that lost everything exits non-zero but still prints a summary, and
    // total loss is a result rather than a failure to measure.
    let text = String::from_utf8_lossy(&out.stdout);
    parse(&text).ok_or_else(|| format!("could not read ping's summary:\n{text}").into())
}

/// Traffic sent to fill the tunnel while the loaded measurement runs.
///
/// Written here rather than shelled out to, because the obvious external tool
/// does not work: flood ping is self-clocked — it sends one packet per reply,
/// with a floor of a hundred a second — so on a ninety-millisecond path it
/// offers about a tenth of a megabit. That is idle. A measurement taken beside
/// it reads as a clean result, which is worse than no measurement at all.
///
/// So: datagrams to the discard port at the same address the probes go to, from
/// as many threads as it takes, as fast as the socket will accept them. It
/// needs no server at the far end, and the far end's refusals cost it nothing.
struct Load {
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

/// How many senders. One socket cannot always fill a link on its own, and a
/// handful costs nothing on a host that is otherwise waiting.
const SENDERS: usize = 4;
/// Datagram size, under any sane tunnel MTU so nothing fragments.
const PAYLOAD: usize = 1200;
/// The discard port, which is refused rather than answered. RFC 863.
const DISCARD: u16 = 9;

impl Load {
    /// Starts sending. Stops when the returned value is dropped or finished.
    fn start(target: Ipv4Addr) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let mut threads = Vec::with_capacity(SENDERS);

        for _ in 0..SENDERS {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            socket.connect((target, DISCARD))?;
            let (stop, sent) = (Arc::clone(&stop), Arc::clone(&sent));
            threads.push(std::thread::spawn(move || {
                let buf = [0u8; PAYLOAD];
                while !stop.load(Ordering::Relaxed) {
                    // An error here is the link pushing back -- a full queue, a
                    // transient unreachable -- which is the condition being
                    // measured rather than a reason to stop.
                    if let Ok(n) = socket.send(&buf) {
                        sent.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }));
        }
        Ok(Self {
            stop,
            sent,
            threads,
        })
    }

    /// Stops sending and reports what was offered, in megabits per second.
    fn finish(self, over: Duration) -> f64 {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads {
            let _ = t.join();
        }
        let bits = self.sent.load(Ordering::Relaxed) as f64 * 8.0;
        bits / over.as_secs_f64() / 1_000_000.0
    }
}

/// `paqetz doctor --under-load`.
///
/// # Errors
/// Returns an error if the configuration cannot be read, or if `ping` is absent
/// or says nothing usable.
pub(crate) fn run(
    path: &std::path::Path,
    name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::Config::load(path)?;
    let tunnel = match name {
        Some(n) => cfg
            .named(n)
            .ok_or_else(|| format!("no tunnel named `{n}` is configured"))?,
        // Naming one is optional with a single tunnel and required with
        // several, rather than silently probing whichever came first.
        None if cfg.tunnels.len() == 1 => cfg.tunnels.first().expect("just counted"),
        None => {
            let names: Vec<_> = cfg.tunnels.iter().map(|t| t.name.as_str()).collect();
            return Err(format!(
                "several tunnels are configured; name one with --tunnel: {}",
                names.join(", ")
            )
            .into());
        }
    };
    let target = tunnel.peer.tunnel_address.to_string();

    println!("Probing {target} through {}.\n", tunnel.interface.device);
    println!("This sends traffic. It changes nothing.\n");

    // Twice, before anything else. A path that has been quiet loses the first
    // packets waking up, and a single run cannot tell that apart from a lossy
    // link -- the second run is the control.
    let cold = probe(&target, IDLE_COUNT)?;
    let warm = probe(&target, IDLE_COUNT)?;

    let load = Load::start(tunnel.peer.tunnel_address)?;
    let started = Instant::now();
    let loaded = probe(&target, LOADED_COUNT);
    let offered = load.finish(started.elapsed());
    let loaded = loaded?;

    report(cold, warm, loaded, offered);
    Ok(())
}

/// Prints the three measurements and what they mean together.
fn report(cold: Sample, warm: Sample, loaded: Sample, offered: f64) {
    println!("                 loss     min      avg      max     mdev");
    for (what, s) in [
        ("idle, first", cold),
        ("idle, again", warm),
        ("under load ", loaded),
    ] {
        println!(
            "  {what}   {:5.1}%  {:6.1}ms {:6.1}ms {:6.1}ms {:6.2}ms",
            s.loss, s.min, s.avg, s.max, s.mdev
        );
    }
    // What the loaded row was actually loaded with. Without this the reader
    // cannot tell a path that stayed flat under pressure from one that was
    // never put under any.
    println!("\n  {offered:.0} Mbit/s offered during the loaded run.");
    println!();

    // The queue question. A few milliseconds is a clean path; hundreds means
    // something is holding packets rather than dropping them, which a
    // throughput test would have reported as success.
    let added = loaded.avg - warm.avg;
    if offered < 1.0 {
        println!("Almost nothing went out during the loaded run, so that row means");
        println!("nothing. The tunnel is probably down, or its address is unreachable.");
    } else if added > 100.0 {
        println!("Latency rose {added:.0}ms under load.");
        println!("Something on this path buffers rather than drops: a transfer will");
        println!("still complete, and everything interactive will suffer while it does.");
    } else if added > 20.0 {
        println!("Latency rose {added:.0}ms under load, which is mild but real.");
    } else if added > 1.0 {
        println!("Latency rose {added:.0}ms under load. The path stays responsive when busy.");
    } else {
        // A negative delta is ordinary measurement noise, and printing it as a
        // rise of "-0ms" reads as a bug in the tool rather than a clean result.
        println!("Latency did not rise under load. The path stays responsive when busy.");
    }

    // The cold-path question, which is what the doubled idle run is for.
    if cold.loss > warm.loss + 5.0 {
        println!();
        println!(
            "The first idle run lost {:.0}% and the second {:.0}%, with the same round",
            cold.loss, warm.loss
        );
        println!("trip times. Nothing is congested — the path had gone cold and the first");
        println!("packets paid to wake it. Set `keepalive = true` under [tunnel.interface]");
        println!("to hold it open.");
    }

    if loaded.loss > 1.0 {
        println!();
        println!(
            "{:.0}% of probes were lost while busy, which is loss rather than delay.",
            loaded.loss
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMMARY: &str = "\
--- 10.7.0.1 ping statistics ---
30 packets transmitted, 21 received, 30% packet loss, time 5879ms
rtt min/avg/max/mdev = 92.940/94.170/96.751/1.183 ms
";

    #[test]
    fn a_summary_is_read_as_it_is_printed() {
        let s = parse(SUMMARY).expect("parse");
        assert!((s.loss - 30.0).abs() < f64::EPSILON);
        assert!((s.min - 92.940).abs() < 0.001);
        assert!((s.avg - 94.170).abs() < 0.001);
        assert!((s.max - 96.751).abs() < 0.001);
        assert!((s.mdev - 1.183).abs() < 0.001);
    }

    #[test]
    fn a_clean_run_reads_as_no_loss() {
        let text = "\
30 packets transmitted, 30 received, 0% packet loss, time 5811ms
rtt min/avg/max/mdev = 92.930/93.212/96.224/0.568 ms
";
        let s = parse(text).expect("parse");
        assert!(s.loss.abs() < f64::EPSILON);
        assert!((s.avg - 93.212).abs() < 0.001);
    }

    #[test]
    fn a_fractional_loss_is_not_rounded_away() {
        // `ping` prints these for counts that do not divide evenly, and reading
        // one as zero would turn a lossy link into a clean report.
        let text = "\
37 packets transmitted, 36 received, 2.7027% packet loss, time 7212ms
rtt min/avg/max/mdev = 90.862/91.036/91.410/0.135 ms
";
        let s = parse(text).expect("parse");
        assert!((s.loss - 2.7027).abs() < 0.001, "got {}", s.loss);
    }

    #[test]
    fn output_without_a_summary_is_refused_rather_than_guessed_at() {
        assert!(parse("").is_none());
        assert!(parse("ping: connect: Network is unreachable").is_none());
        // Total loss prints no rtt line at all, and there is nothing to report.
        assert!(parse("30 packets transmitted, 0 received, 100% packet loss, time 5s\n").is_none());
    }
}
