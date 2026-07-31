//! Working out where to send a frame that bypasses the routing table.
//!
//! The `IP_HDRINCL` transmit path needs none of this: the kernel does the route
//! lookup and resolves the next hop itself. The `AF_PACKET` path skips both, so
//! it has to answer the same two questions — which host is the next hop, and
//! what is its hardware address.
//!
//! paqet asked the operator for the second, by hand, in the configuration. That
//! broke silently whenever the gateway changed, a DHCP lease moved, or the host
//! joined another network, and produced the same symptom as every other
//! misconfiguration: a tunnel that carries nothing. Here both are read from the
//! kernel, and re-read when a send fails.

use std::io;
use std::net::Ipv4Addr;

/// A hardware address.
pub type Mac = [u8; 6];

/// One row of the kernel's IPv4 routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Route {
    destination: u32,
    gateway: u32,
    mask: u32,
}

/// Finds the next hop toward `dst`: either a gateway, or `dst` itself.
///
/// A route with no gateway is on-link, meaning the destination is directly
/// reachable and is its own next hop. Getting this wrong is not subtle in the
/// usual case — a wrong hardware address means nothing arrives — but it is
/// invisible on a network where the gateway happens to also be the peer.
///
/// # Errors
/// Returns an error if the routing table cannot be read or has no route.
pub fn next_hop(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    next_hop_from(&table, dst).ok_or_else(|| io::Error::other(format!("no route to {dst}")))
}

/// The parsing half of [`next_hop`], separated so it can be tested.
fn next_hop_from(table: &str, dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let target = u32::from_be_bytes(dst.octets());
    let mut best: Option<Route> = None;

    for line in table.lines().skip(1) {
        let Some(route) = parse_route(line) else {
            continue;
        };
        if target & route.mask != route.destination & route.mask {
            continue;
        }
        // Longest prefix wins, which for a mask means the most bits set.
        if best.is_none_or(|b| route.mask.count_ones() > b.mask.count_ones()) {
            best = Some(route);
        }
    }

    let route = best?;
    if route.gateway == 0 {
        // On-link: the destination is reachable directly.
        Some(dst)
    } else {
        Some(Ipv4Addr::from(route.gateway.to_be_bytes()))
    }
}

/// Parses one `/proc/net/route` row.
///
/// The address columns are little-endian hexadecimal, which is why each is byte
/// swapped after parsing rather than read as a big-endian address.
fn parse_route(line: &str) -> Option<Route> {
    let mut f = line.split_whitespace();
    let _iface = f.next()?;
    let destination = u32::from_str_radix(f.next()?, 16).ok()?.swap_bytes();
    let gateway = u32::from_str_radix(f.next()?, 16).ok()?.swap_bytes();
    let flags = u32::from_str_radix(f.next()?, 16).ok()?;
    // Columns 4..7 are RefCnt, Use and Metric.
    let mask = u32::from_str_radix(f.nth(3)?, 16).ok()?.swap_bytes();

    // Only routes that are up are usable.
    if flags & 0x0001 == 0 {
        return None;
    }
    Some(Route {
        destination,
        gateway,
        mask,
    })
}

/// Looks up the hardware address of a neighbour.
///
/// # Errors
/// Returns an error if the neighbour table cannot be read, or holds no usable
/// entry for `addr`.
pub fn hardware_address(addr: Ipv4Addr) -> io::Result<Mac> {
    let table = std::fs::read_to_string("/proc/net/arp")?;
    hardware_address_from(&table, addr).ok_or_else(|| {
        io::Error::other(format!(
            "no hardware address known for {addr}; the neighbour table has no \
             usable entry"
        ))
    })
}

/// The parsing half of [`hardware_address`], separated so it can be tested.
fn hardware_address_from(table: &str, addr: Ipv4Addr) -> Option<Mac> {
    let wanted = addr.to_string();
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let ip = f.next()?;
        if ip != wanted {
            continue;
        }
        let _hw_type = f.next()?;
        let flags = u32::from_str_radix(f.next()?.trim_start_matches("0x"), 16).ok()?;
        // 0x2 is ATF_COM: the entry is complete. An incomplete entry has a MAC
        // of all zeros, which would be accepted as valid and send every frame
        // into a black hole.
        if flags & 0x2 == 0 {
            continue;
        }
        return parse_mac(f.next()?);
    }
    None
}

/// Parses `aa:bb:cc:dd:ee:ff`.
fn parse_mac(text: &str) -> Option<Mac> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for slot in &mut mac {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    // An all-zero address is what an unresolved entry looks like.
    if mac == [0; 6] { None } else { Some(mac) }
}

/// Provokes the kernel into resolving a neighbour, then waits briefly for it.
///
/// Connecting and sending one byte to a discard port is enough to make the
/// kernel emit an ARP request; the datagram itself is irrelevant and goes
/// nowhere. Without this, the first frame after start-up would be sent to an
/// address we have no entry for.
///
/// # Errors
/// Returns an error if the neighbour is still unresolved when the wait expires.
pub fn resolve(addr: Ipv4Addr) -> io::Result<Mac> {
    if let Ok(mac) = hardware_address(addr) {
        return Ok(mac);
    }

    // Port 9 is discard. Nothing is expected to answer, and nothing needs to.
    if let Ok(sock) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        let _ = sock.send_to(&[0u8], (addr, 9));
    }

    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Ok(mac) = hardware_address(addr) {
            return Ok(mac);
        }
    }
    Err(io::Error::other(format!(
        "could not resolve the hardware address of {addr} after one second"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table shaped like the kernel's: on-link subnet, then a default route.
    const TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp3s0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
enp3s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    #[test]
    fn an_on_link_destination_is_its_own_next_hop() {
        // 192.168.0.0/24 is on-link, so 192.168.0.50 is reached directly.
        assert_eq!(
            next_hop_from(TABLE, Ipv4Addr::new(192, 168, 0, 50)),
            Some(Ipv4Addr::new(192, 168, 0, 50))
        );
    }

    #[test]
    fn anything_else_goes_via_the_gateway() {
        assert_eq!(
            next_hop_from(TABLE, Ipv4Addr::new(8, 8, 8, 8)),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn the_most_specific_route_wins() {
        let table =
            format!("{TABLE}enp3s0\t08080808\t0201A8C0\t0003\t0\t0\t100\tFFFFFFFF\t0\t0\t0\n");
        assert_eq!(
            next_hop_from(&table, Ipv4Addr::new(8, 8, 8, 8)),
            Some(Ipv4Addr::new(192, 168, 1, 2)),
            "a /32 must beat the default route"
        );
        // And an address the /32 does not cover still takes the default.
        assert_eq!(
            next_hop_from(&table, Ipv4Addr::new(8, 8, 4, 4)),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn a_route_that_is_down_is_ignored() {
        // Without the up flag there is nothing usable, on-link or otherwise.
        let table = "Iface\tDest\tGw\tFlags\tR\tU\tM\tMask\nenp3s0\t00000000\t0101A8C0\t0000\t0\t0\t0\t00000000\n";
        assert_eq!(next_hop_from(table, Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn a_table_with_no_matching_route_yields_nothing() {
        let only_on_link = "Iface\tDest\tGw\tFlags\tR\tU\tM\tMask\nenp3s0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(next_hop_from(only_on_link, Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn malformed_route_tables_do_not_panic() {
        for table in ["", "header\n", "a\n", "a\tb\n", "a\tb\tc\td\n", "\n\n"] {
            let _ = next_hop_from(table, Ipv4Addr::LOCALHOST);
        }
    }

    #[test]
    fn a_complete_neighbour_entry_is_read() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        enp3s0
";
        assert_eq!(
            hardware_address_from(arp, Ipv4Addr::new(192, 168, 1, 1)),
            Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn an_incomplete_neighbour_entry_is_refused() {
        // Flags without ATF_COM means resolution is still in progress, and the
        // address column is all zeros. Accepting it would send every frame into
        // a black hole with no error anywhere.
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x0         00:00:00:00:00:00     *        enp3s0
";
        assert_eq!(
            hardware_address_from(arp, Ipv4Addr::new(192, 168, 1, 1)),
            None
        );
    }

    #[test]
    fn an_all_zero_address_is_refused_even_if_flagged_complete() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:00:00:00:00:00     *        enp3s0
";
        assert_eq!(
            hardware_address_from(arp, Ipv4Addr::new(192, 168, 1, 1)),
            None
        );
    }

    #[test]
    fn an_absent_neighbour_yields_nothing() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        enp3s0
";
        assert_eq!(hardware_address_from(arp, Ipv4Addr::new(10, 0, 0, 1)), None);
    }

    #[test]
    fn malformed_neighbour_tables_do_not_panic() {
        for arp in [
            "",
            "header\n",
            "1.2.3.4\n",
            "1.2.3.4 0x1\n",
            "1.2.3.4 0x1 0xz aa\n",
        ] {
            let _ = hardware_address_from(arp, Ipv4Addr::new(1, 2, 3, 4));
        }
    }

    #[test]
    fn hardware_addresses_are_parsed_strictly() {
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None, "too few octets");
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None, "too many octets");
        assert_eq!(parse_mac("zz:bb:cc:dd:ee:ff"), None, "not hexadecimal");
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn the_hosts_own_routing_table_parses() {
        // Read-only, and tolerant of a host with no default route.
        if let Ok(table) = std::fs::read_to_string("/proc/net/route") {
            let _ = next_hop_from(&table, Ipv4Addr::new(1, 1, 1, 1));
        }
    }
}
