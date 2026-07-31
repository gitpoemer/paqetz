//! `paqetz` — point-to-point L3 tunnel over crafted TCP segments.
//!
//! Phase 0 scaffold: the command surface is fixed here so the crate graph and
//! CI are real, but no subcommand is implemented yet. See
//! `docs/08-rewrite-plan.md` §8.5 for what lands in phase 1.

fn main() {
    println!(
        "paqetz {} — scaffold. No subcommand is implemented yet (phase 0).",
        env!("CARGO_PKG_VERSION")
    );
}
