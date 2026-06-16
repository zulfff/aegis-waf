use std::net::IpAddr;
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use ipnet::IpNet;
use parking_lot::RwLock;

use crate::config::IngressFilterConfig;
use crate::error::{AegisError, Result};

const DEFAULT_CONNECTION_LIMIT_PER_IP: u64 = 1000;
#[allow(dead_code)]
const DEFAULT_MAX_PACKET_SIZE: u64 = 65535;
const SYN_FLOOD_THRESHOLD: u64 = 100;
const SYN_FLOOD_WINDOW_SECS: u64 = 5;
const CONNECTION_EXPIRY_SECS: u64 = 300;
const CLEANUP_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub key: ConnectionKey,
    pub tcp_state: TcpState,
    pub created: Instant,
    pub last_seen: Instant,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: Option<u8>,
    pub payload_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Allow,
    Block(&'static str),
    Challenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reputation {
    Clean,
    Suspect,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone)]
struct PerIpStats {
    connection_count: u64,
    blocked_count: u64,
    syn_count: u64,
    syn_window_start: Instant,
    last_seen: Instant,
}

impl PerIpStats {
    fn new() -> Self {
        Self {
            connection_count: 0,
            blocked_count: 0,
            syn_count: 0,
            syn_window_start: Instant::now(),
            last_seen: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct IngressFilter {
    #[allow(dead_code)]
    config: IngressFilterConfig,
    connections: RwLock<HashMap<ConnectionKey, ConnectionState>>,
    ip_stats: RwLock<HashMap<IpAddr, PerIpStats>>,
    blocked_ips: RwLock<Vec<IpNet>>,
    allowed_ips: RwLock<Vec<IpNet>>,
    syn_flood_threshold: u64,
    syn_flood_window: Duration,
    connection_limit_per_ip: u64,
    max_packet_size: u64,
    last_cleanup: RwLock<Instant>,
}

impl IngressFilter {
    pub fn new(config: IngressFilterConfig) -> Result<Self> {
        let blocked: Result<Vec<IpNet>> = config
            .blocked_ip_ranges
            .iter()
            .map(|r| {
                r.parse::<IpNet>().map_err(|e| {
                    AegisError::ConfigError(format!("Invalid blocked IP range '{}': {}", r, e))
                })
            })
            .collect();

        let allowed: Result<Vec<IpNet>> = config
            .allowed_ip_ranges
            .iter()
            .map(|r| {
                r.parse::<IpNet>().map_err(|e| {
                    AegisError::ConfigError(format!("Invalid allowed IP range '{}': {}", r, e))
                })
            })
            .collect();

        Ok(Self {
            blocked_ips: RwLock::new(blocked?),
            allowed_ips: RwLock::new(allowed?),
            connections: RwLock::new(HashMap::new()),
            ip_stats: RwLock::new(HashMap::new()),
            syn_flood_threshold: SYN_FLOOD_THRESHOLD,
            syn_flood_window: Duration::from_secs(SYN_FLOOD_WINDOW_SECS),
            connection_limit_per_ip: DEFAULT_CONNECTION_LIMIT_PER_IP,
            max_packet_size: config.max_packet_size,
            last_cleanup: RwLock::new(Instant::now()),
            config,
        })
    }

    pub fn validate_packet(&self, packet: &PacketInfo) -> Result<FilterDecision> {
        if packet.payload_size > self.max_packet_size {
            return Ok(FilterDecision::Block("packet exceeds maximum size"));
        }

        if packet.payload_size == 0 && packet.protocol == 6 {
            if let Some(flags) = packet.tcp_flags {
                if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                    let syn_flood = {
                        let mut stats = self.ip_stats.write();
                        let entry = stats.entry(packet.src_ip).or_insert_with(PerIpStats::new);

                        let elapsed = entry.syn_window_start.elapsed();
                        if elapsed >= self.syn_flood_window {
                            entry.syn_count = 0;
                            entry.syn_window_start = Instant::now();
                        }
                        entry.syn_count = entry.syn_count.saturating_add(1);
                        entry.syn_count > self.syn_flood_threshold
                    };

                    if syn_flood {
                        return Ok(FilterDecision::Block("SYN flood detected"));
                    }
                }
            }
        }

        if let Some(flags) = packet.tcp_flags {
            if !Self::tcp_flags_are_valid(flags) {
                return Ok(FilterDecision::Block("invalid TCP flags combination"));
            }
        }

        let conn_count = {
            let stats = self.ip_stats.read();
            stats
                .get(&packet.src_ip)
                .map(|s| s.connection_count)
                .unwrap_or(0)
        };

        if conn_count >= self.connection_limit_per_ip {
            return Ok(FilterDecision::Block("per-IP connection limit exceeded"));
        }

        self.maybe_cleanup_connections();

        Ok(FilterDecision::Allow)
    }

    pub fn check_ip_reputation(&self, ip: IpAddr) -> Reputation {
        let blocked = self.blocked_ips.read();
        for range in blocked.iter() {
            if range.contains(&ip) {
                return Reputation::Malicious;
            }
        }

        let allowed = self.allowed_ips.read();
        for range in allowed.iter() {
            if range.contains(&ip) {
                return Reputation::Clean;
            }
        }

        Reputation::Unknown
    }

    pub fn is_connection_allowed(&self, packet: &PacketInfo) -> Result<FilterDecision> {
        let reputation = self.check_ip_reputation(packet.src_ip);
        if reputation == Reputation::Malicious {
            return Ok(FilterDecision::Block("IP in blocked range"));
        }

        let key = ConnectionKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        let is_new = {
            let conns = self.connections.read();
            !conns.contains_key(&key)
        };

        if is_new {
            let mut conns = self.connections.write();
            if let hashbrown::hash_map::Entry::Vacant(e) = conns.entry(key) {
                let tcp_state = if let Some(flags) = packet.tcp_flags {
                    if (flags & 0x02) != 0 {
                        TcpState::SynSent
                    } else {
                        TcpState::Established
                    }
                } else {
                    TcpState::Established
                };

                e.insert(ConnectionState {
                    key,
                    tcp_state,
                    created: Instant::now(),
                    last_seen: Instant::now(),
                    packet_count: 1,
                    byte_count: packet.payload_size,
                });
            }

            let mut stats = self.ip_stats.write();
            let entry = stats.entry(packet.src_ip).or_insert_with(PerIpStats::new);
            entry.connection_count = entry.connection_count.saturating_add(1);
            entry.last_seen = Instant::now();
        } else {
            let mut conns = self.connections.write();
            if let Some(state) = conns.get_mut(&key) {
                state.last_seen = Instant::now();
                state.packet_count = state.packet_count.saturating_add(1);
                state.byte_count = state.byte_count.saturating_add(packet.payload_size);

                if let Some(flags) = packet.tcp_flags {
                    state.tcp_state = Self::transition_tcp_state(state.tcp_state, flags);
                }
            }
        }

        Ok(FilterDecision::Allow)
    }

    pub fn register_connection(&self, packet: &PacketInfo) {
        let key = ConnectionKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        let mut conns = self.connections.write();
        conns.entry(key).or_insert_with(|| {
            let tcp_state = if let Some(flags) = packet.tcp_flags {
                if (flags & 0x02) != 0 {
                    TcpState::SynSent
                } else {
                    TcpState::Established
                }
            } else {
                TcpState::Established
            };

            ConnectionState {
                key,
                tcp_state,
                created: Instant::now(),
                last_seen: Instant::now(),
                packet_count: 0,
                byte_count: 0,
            }
        });
    }

    pub fn remove_connection(&self, packet: &PacketInfo) {
        let key = ConnectionKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        let mut conns = self.connections.write();
        conns.remove(&key);

        let mut stats = self.ip_stats.write();
        if let Some(entry) = stats.get_mut(&packet.src_ip) {
            entry.connection_count = entry.connection_count.saturating_sub(1);
        }
    }

    pub fn add_blocked_range(&self, range: &str) -> Result<()> {
        let net: IpNet = range
            .parse::<IpNet>()
            .map_err(|e| AegisError::ConfigError(format!("Invalid IP range '{}': {}", range, e)))?;
        self.blocked_ips.write().push(net);
        Ok(())
    }

    pub fn add_allowed_range(&self, range: &str) -> Result<()> {
        let net: IpNet = range
            .parse::<IpNet>()
            .map_err(|e| AegisError::ConfigError(format!("Invalid IP range '{}': {}", range, e)))?;
        self.allowed_ips.write().push(net);
        Ok(())
    }

    pub fn block_ip(&self, ip: IpAddr) {
        if let Ok(net) = format!("{}/32", ip).parse::<IpNet>() {
            self.blocked_ips.write().push(net);
        }
        let mut stats = self.ip_stats.write();
        if let Some(entry) = stats.get_mut(&ip) {
            entry.blocked_count = entry.blocked_count.saturating_add(1);
        }
    }

    pub fn unblock_ip(&self, ip: IpAddr) {
        let mut blocked = self.blocked_ips.write();
        blocked.retain(|net| match (ip, net) {
            (IpAddr::V4(v4), IpNet::V4(net4)) => !net4.contains(&v4),
            (IpAddr::V6(v6), IpNet::V6(net6)) => !net6.contains(&v6),
            _ => true,
        });
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    pub fn connection_count_for_ip(&self, ip: IpAddr) -> u64 {
        let stats = self.ip_stats.read();
        stats.get(&ip).map(|s| s.connection_count).unwrap_or(0)
    }

    fn tcp_flags_are_valid(flags: u8) -> bool {
        if (flags & 0x01) != 0 && (flags & 0x04) != 0 {
            return false;
        }
        if (flags & 0x02) != 0 && (flags & 0x14) != 0 {
            return false;
        }
        if flags == 0x00 {
            return false;
        }
        if (flags & 0x02) != 0 && (flags & 0x01) != 0 {
            return false;
        }
        true
    }

    fn transition_tcp_state(current: TcpState, flags: u8) -> TcpState {
        let syn = (flags & 0x02) != 0;
        let ack = (flags & 0x10) != 0;
        let fin = (flags & 0x01) != 0;
        let rst = (flags & 0x04) != 0;

        if rst {
            return TcpState::Closed;
        }

        match current {
            TcpState::SynSent if syn && ack => TcpState::SynReceived,
            TcpState::SynReceived if ack && !syn && !fin => TcpState::Established,
            TcpState::SynSent if ack && !syn => TcpState::Established,
            TcpState::Established if fin && ack => TcpState::FinWait1,
            TcpState::FinWait1 if fin && ack => TcpState::Closing,
            TcpState::FinWait1 if ack && !fin => TcpState::FinWait2,
            TcpState::FinWait2 if fin => TcpState::TimeWait,
            TcpState::LastAck if ack && !fin => TcpState::Closed,
            TcpState::Closing if ack && !fin => TcpState::TimeWait,
            _ => current,
        }
    }

    fn maybe_cleanup_connections(&self) {
        let mut last_cleanup = self.last_cleanup.write();
        if last_cleanup.elapsed() < Duration::from_secs(CLEANUP_INTERVAL_SECS) {
            return;
        }
        *last_cleanup = Instant::now();
        drop(last_cleanup);

        let expiry = Duration::from_secs(CONNECTION_EXPIRY_SECS);
        let now = Instant::now();

        let mut conns = self.connections.write();
        conns.retain(|_key, state| {
            if now.duration_since(state.last_seen) >= expiry {
                return false;
            }
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IngressFilterConfig;

    fn test_config() -> IngressFilterConfig {
        IngressFilterConfig {
            enable_geoip: false,
            geoip_db_path: None,
            blocked_countries: vec![],
            blocked_ip_ranges: vec![],
            allowed_ip_ranges: vec![],
            max_packet_size: 65535,
        }
    }

    fn test_packet() -> PacketInfo {
        PacketInfo {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(0x02),
            payload_size: 0,
        }
    }

    #[test]
    fn test_packet_size_exceeded() {
        let mut cfg = test_config();
        cfg.max_packet_size = 100;
        let filter = IngressFilter::new(cfg).unwrap();
        let pkt = PacketInfo {
            payload_size: 200,
            ..test_packet()
        };
        let decision = filter.validate_packet(&pkt).unwrap();
        assert_eq!(
            decision,
            FilterDecision::Block("packet exceeds maximum size")
        );
    }

    #[test]
    fn test_packet_within_limits() {
        let filter = IngressFilter::new(test_config()).unwrap();
        let pkt = test_packet();
        let decision = filter.validate_packet(&pkt).unwrap();
        assert_eq!(decision, FilterDecision::Allow);
    }

    #[test]
    fn test_ip_reputation_blocked() {
        let mut cfg = test_config();
        cfg.blocked_ip_ranges = vec!["192.168.1.0/24".to_string()];
        let filter = IngressFilter::new(cfg).unwrap();
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(filter.check_ip_reputation(ip), Reputation::Malicious);
    }

    #[test]
    fn test_ip_reputation_allowed() {
        let mut cfg = test_config();
        cfg.allowed_ip_ranges = vec!["10.0.0.0/8".to_string()];
        let filter = IngressFilter::new(cfg).unwrap();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(filter.check_ip_reputation(ip), Reputation::Clean);
    }

    #[test]
    fn test_ip_reputation_unknown() {
        let filter = IngressFilter::new(test_config()).unwrap();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(filter.check_ip_reputation(ip), Reputation::Unknown);
    }

    #[test]
    fn test_connection_tracking() {
        let filter = IngressFilter::new(test_config()).unwrap();
        let pkt = test_packet();
        assert_eq!(
            filter.is_connection_allowed(&pkt).unwrap(),
            FilterDecision::Allow
        );
        assert_eq!(filter.connection_count(), 1);
    }

    #[test]
    fn test_blocked_ip_rejected() {
        let mut cfg = test_config();
        cfg.blocked_ip_ranges = vec!["192.168.1.0/24".to_string()];
        let filter = IngressFilter::new(cfg).unwrap();
        let pkt = test_packet();
        assert_eq!(
            filter.is_connection_allowed(&pkt).unwrap(),
            FilterDecision::Block("IP in blocked range")
        );
    }

    #[test]
    fn test_block_and_unblock_ip() {
        let filter = IngressFilter::new(test_config()).unwrap();
        let ip: IpAddr = "10.10.10.10".parse().unwrap();
        filter.block_ip(ip);
        assert_eq!(filter.check_ip_reputation(ip), Reputation::Malicious);
        filter.unblock_ip(ip);
        assert_eq!(filter.check_ip_reputation(ip), Reputation::Unknown);
    }

    #[test]
    fn test_remove_connection() {
        let filter = IngressFilter::new(test_config()).unwrap();
        let pkt = test_packet();
        filter.register_connection(&pkt);
        assert_eq!(filter.connection_count(), 1);
        filter.remove_connection(&pkt);
        assert_eq!(filter.connection_count(), 0);
    }

    #[test]
    fn test_invalid_blocked_range_errors() {
        let mut cfg = test_config();
        cfg.blocked_ip_ranges = vec!["not-an-ip".to_string()];
        assert!(IngressFilter::new(cfg).is_err());
    }

    #[test]
    fn test_invalid_allowed_range_errors() {
        let mut cfg = test_config();
        cfg.allowed_ip_ranges = vec!["not-an-ip".to_string()];
        assert!(IngressFilter::new(cfg).is_err());
    }
}
