//! Diagnostic logging to stdout.
//!
//! Deliberately not a logging framework and deliberately not metrics. There is
//! no endpoint, no socket, and nothing to scrape — just lines a person reads
//! when something is obviously wrong.
//!
//! # Cost when it is off
//!
//! The level is one relaxed atomic load, and the macros check it *before*
//! evaluating their arguments, so a disabled `debug!` costs a load and a
//! predictable branch — no formatting, no allocation, no lock.
//!
//! The hot paths do not call these macros at all. Per-packet events increment a
//! counter in [`crate::stats`] and are reported in aggregate, which is both
//! cheaper and the only safe design: see that module for why a log line per
//! packet is a denial-of-service vector rather than merely noisy.

use std::sync::atomic::{AtomicU8, Ordering};

/// How much to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum Level {
    /// Nothing at all.
    Off = 0,
    /// Something is broken.
    Error = 1,
    /// Something is suspicious but the tunnel continues.
    Warn = 2,
    /// Lifecycle events: handshakes, roaming, rekeys, the health line.
    Info = 3,
    /// Everything, including per-event detail. Not for steady use.
    Debug = 4,
}

impl Level {
    /// Parses a configured level name.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }

    /// The name this level is configured under.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Every level that can be configured, for error messages.
    pub(crate) const ALL: &'static [&'static str] = &["off", "error", "warn", "info", "debug"];
}

/// The active level. Read on every logging decision, written on reload.
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Sets the active level.
pub(crate) fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// The active level.
pub(crate) fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        _ => Level::Debug,
    }
}

/// Whether a message at `level` would be printed.
///
/// A relaxed load and a comparison. Inlined so a disabled call site is a
/// predictable branch over the formatting that would follow.
#[inline]
pub(crate) fn enabled(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// Prints one line. Called only after [`enabled`] has said yes.
pub(crate) fn emit(level: Level, args: std::fmt::Arguments<'_>) {
    let tag = match level {
        Level::Off => return,
        Level::Error => "error",
        Level::Warn => "warn ",
        Level::Info => "info ",
        Level::Debug => "debug",
    };
    // Uptime rather than wall-clock: it needs no timezone handling, and "what
    // happened 3 seconds before it broke" is the question logs get asked.
    println!("[{:>9.3}] {tag} {args}", uptime().as_secs_f64());
}

/// Seconds since the process started.
pub(crate) fn uptime() -> std::time::Duration {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// Starts the uptime clock, so the first line does not read as zero.
pub(crate) fn init() {
    let _ = uptime();
}

macro_rules! error {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Error) {
            $crate::log::emit($crate::log::Level::Error, format_args!($($arg)*));
        }
    };
}

macro_rules! warn_ {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Warn) {
            $crate::log::emit($crate::log::Level::Warn, format_args!($($arg)*));
        }
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Info) {
            $crate::log::emit($crate::log::Level::Info, format_args!($($arg)*));
        }
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Debug) {
            $crate::log::emit($crate::log::Level::Debug, format_args!($($arg)*));
        }
    };
}

pub(crate) use {debug, error, info, warn_};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_configurable_name_parses_back_to_itself() {
        for name in Level::ALL {
            let level = Level::parse(name).unwrap_or_else(|| panic!("{name} should parse"));
            assert_eq!(level.name(), *name);
        }
    }

    #[test]
    fn an_unknown_level_does_not_parse() {
        assert_eq!(Level::parse("verbose"), None);
        assert_eq!(Level::parse(""), None);
        assert_eq!(Level::parse("INFO"), None, "names are lower case");
    }

    #[test]
    fn levels_order_from_quiet_to_loud() {
        assert!(Level::Off < Level::Error);
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn enabling_a_level_enables_everything_above_it() {
        // Serialised through one global, so this test owns it for its duration.
        set_level(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));

        set_level(Level::Off);
        assert!(!enabled(Level::Error));
        assert!(!enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));

        set_level(Level::Debug);
        assert!(enabled(Level::Error) && enabled(Level::Debug));

        set_level(Level::Info);
    }

    #[test]
    fn a_disabled_macro_does_not_evaluate_its_arguments() {
        // The property that makes logging free when it is off: an expensive
        // argument must not be computed to then be discarded.
        use std::sync::atomic::AtomicUsize;
        static CALLS: AtomicUsize = AtomicUsize::new(0);

        fn expensive() -> usize {
            CALLS.fetch_add(1, Ordering::Relaxed)
        }

        set_level(Level::Off);
        debug!("{}", expensive());
        error!("{}", expensive());
        assert_eq!(
            CALLS.load(Ordering::Relaxed),
            0,
            "arguments must not be evaluated when the level is off"
        );

        set_level(Level::Debug);
        debug!("{}", expensive());
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);

        set_level(Level::Info);
    }
}
