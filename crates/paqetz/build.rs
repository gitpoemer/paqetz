//! Records the target this binary was built for.
//!
//! `paqetz update` has to fetch the same build it is replacing, and there is no
//! way to work that out at run time: `uname -m` gives the architecture but not
//! whether this is the musl or the glibc build, and swapping one for the other
//! produces a binary that either will not start or quietly loses the property
//! it was chosen for. Cargo knows the answer at build time, so it is recorded
//! here rather than guessed later.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=PAQETZ_TARGET={target}");
    println!("cargo:rerun-if-env-changed=TARGET");
}
