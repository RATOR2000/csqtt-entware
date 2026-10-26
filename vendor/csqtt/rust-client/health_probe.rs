// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bounded, read-only router health probes. This mode must run before daemon
//! initialization: it never opens the persistent identity or authenticates VK.

use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
    task::JoinSet,
    time::timeout,
};

const MAX_INPUT: usize = 8192;
const MAX_DNS: usize = 4096;
const MAX_BODY: usize = 4096;
const TOTAL_LIMIT: Duration = Duration::from_secs(10);
const INPUT_LIMIT: Duration = Duration::from_secs(1);
const DNS_LIMIT: Duration = Duration::from_secs(3);
const HTTPS_LIMIT: Duration = Duration::from_secs(5);
const VPN_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const ENDPOINTS: [(&str, &str); 2] = [
    ("www.cloudflare.com", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("dns.google", "https://dns.google/resolve?name=example.com&type=A"),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode { Vpn, Wan }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    mode: Option<Mode>,
    source_ipv4: Ipv4Addr,
    dns_ipv4: Ipv4Addr,
    #[serde(default)]
    group_ports: Vec<u16>,
}

impl Input {
    fn valid(&self, mode: Mode) -> bool {
        if mode == Mode::Vpn && !cfg!(target_os = "linux") { return false; }
        if self.mode.is_some_and(|value| value != mode)
            || !unicast(self.source_ipv4) || !unicast(self.dns_ipv4)
            || self.group_ports.len() > 16
            || (mode == Mode::Vpn) != (self.source_ipv4 == VPN_SOURCE)
        { return false; }
        for (index, port) in self.group_ports.iter().enumerate() {
            if !(5400..=5415).contains(port) || self.group_ports[..index].contains(port) {
                return false;
            }
        }
        true
    }
}

fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State { Ok, Fail, Unknown, EndpointError, NotAttempted, NotChecked }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    None, Timeout, TransportError, InvalidReply, Truncated, Rejected,
    NoAnswers, HttpStatus, BodyLimit, BodyError, Internal,
}

#[derive(Debug, Serialize)]
struct EndpointResult {
    index: usize,
    state: State,
    dns: State,
    https: State,
    reachable: bool,
    dns_reason: Reason,
    https_reason: Reason,
}

impl EndpointResult {
    fn unknown(index: usize) -> Self {
        Self { index, state: State::Unknown, dns: State::Unknown,
            https: State::NotAttempted, reachable: false,
            dns_reason: Reason::None, https_reason: Reason::None }
    }
}

#[derive(Debug, Serialize)]
struct GroupResult { index: usize, udp: State, tcp: State }

#[derive(Debug, Serialize)]
struct Observation {
    schema_version: u8,
    mode: Option<Mode>,
    config_valid: bool,
    completed: bool,
    path: State,
    endpoints: Vec<EndpointResult>,
    groups: Vec<GroupResult>,
    group_dns: State,
    elapsed_ms: u64,
}

impl Observation {
    fn empty(mode: Option<Mode>) -> Self {
        Self { schema_version: 1, mode, config_valid: false, completed: false,
            path: State::Unknown, endpoints: (0..2).map(EndpointResult::unknown).collect(),
            groups: Vec::new(), group_dns: State::NotChecked, elapsed_ms: 0 }
    }

    fn aggregate(&mut self) {
        self.path = if self.endpoints.iter().any(|result| result.state == State::Ok) {
            State::Ok
        } else if self.endpoints.iter().any(|result| result.reachable) {
            State::EndpointError
        } else if self.endpoints.iter().all(|result| result.state == State::Fail) {
            State::Fail
        } else { State::Unknown };
        self.group_dns = if self.groups.is_empty() { State::NotChecked }
        else if self.groups.iter().all(|result| result.udp == State::Ok && result.tcp == State::Ok) { State::Ok }
        else if self.groups.iter().any(|result| result.udp == State::Fail || result.tcp == State::Fail) { State::Fail }
        else { State::Unknown };
    }
}

fn parse_input(mode: Mode, bytes: &[u8]) -> Option<Input> {
    if bytes.len() > MAX_INPUT { return None; }
    let input: Input = serde_json::from_slice(bytes).ok()?;
    input.valid(mode).then_some(input)
}

/// Emit one redacted JSON line. Zero means a complete observation, including
/// unhealthy results; 2 means invalid input; 1 means an internal/incomplete run.
/// The caller should exit immediately with this code, before daemon::prepare.
pub fn run_cli(mode: &str) -> i32 {
    let start = Instant::now();
    let mode = match mode { "vpn" => Some(Mode::Vpn), "wan" => Some(Mode::Wan), _ => None };
    let mut observation = Observation::empty(mode);
    let mut code = 2;
    if let Some(mode) = mode {
        // A producer that forgets EOF must not defeat the total deadline. A
        // blocked reader thread is discarded when this short-lived mode exits.
        let (send, receive) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new().name("health-input".into()).spawn(move || {
            let mut bytes = Vec::new();
            let read = std::io::stdin().take((MAX_INPUT + 1) as u64).read_to_end(&mut bytes);
            let _ = send.send(read.ok().map(|_| bytes));
        });
        if spawned.is_ok() {
            if let Ok(Some(bytes)) = receive.recv_timeout(INPUT_LIMIT) {
                if let Some(input) = parse_input(mode, &bytes) {
                    observation.config_valid = true;
                    code = 1;
                    if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        observation = runtime.block_on(observe(mode, input, start));
                        if observation.completed { code = 0; }
                    }
                }
            }
        }
    }
    observation.elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let mut output = std::io::stdout().lock();
    if serde_json::to_writer(&mut output, &observation).is_err() || output.write_all(b"\n").is_err() {
        return 1;
    }
    code
}

enum TaskResult { Endpoint(EndpointResult), Group(usize, bool, State) }

async fn observe(mode: Mode, input: Input, start: Instant) -> Observation {
    let mut observation = Observation::empty(Some(mode));
    observation.config_valid = true;
    observation.groups = input.group_ports.iter().enumerate()
        .map(|(index, _)| GroupResult { index, udp: State::Unknown, tcp: State::Unknown }).collect();
    let mut tasks = JoinSet::new();
    for index in 0..ENDPOINTS.len() {
        let source = input.source_ipv4;
        let resolver = SocketAddr::from((input.dns_ipv4, 53));
        tasks.spawn(async move { TaskResult::Endpoint(probe_endpoint(index, source, resolver).await) });
    }
    for (index, port) in input.group_ports.iter().copied().enumerate() {
        for tcp in [false, true] {
            tasks.spawn(async move {
                let result = dns_query(Ipv4Addr::LOCALHOST, SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "example.com", tcp).await;
                TaskResult::Group(index, tcp, if result.is_ok() { State::Ok } else { State::Fail })
            });
        }
    }
    let remaining = TOTAL_LIMIT.saturating_sub(start.elapsed());
    let completed = timeout(remaining, async {
        let mut intact = true;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(TaskResult::Endpoint(value)) => { let index = value.index; observation.endpoints[index] = value; }
                Ok(TaskResult::Group(index, tcp, value)) => {
                    if tcp { observation.groups[index].tcp = value; } else { observation.groups[index].udp = value; }
                }
                Err(_) => { intact = false; }
            }
        }
        intact
    }).await;
    observation.completed = matches!(completed, Ok(true));
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    observation.aggregate();
    observation
}

async fn probe_endpoint(index: usize, source: Ipv4Addr, resolver: SocketAddr) -> EndpointResult {
    let mut result = EndpointResult::unknown(index);
    let (host, url) = ENDPOINTS[index];
    let addresses = match dns_query(source, resolver, host, false).await {
        Ok(addresses) => { result.dns = State::Ok; addresses }
        Err(reason) => {
            result.state = State::Fail; result.dns = State::Fail; result.dns_reason = reason;
            return result;
        }
    };
    let addresses: Vec<_> = addresses.into_iter().map(|ip| SocketAddr::from((ip, 443))).collect();
    let builder = primp::Client::builder().local_address(IpAddr::V4(source));
    #[cfg(target_os = "linux")]
    let builder = if source == VPN_SOURCE { builder.interface("csqtt0") } else { builder };
    let client = match builder
        .resolve_to_addrs(host, &addresses).no_proxy().redirect(primp::redirect::Policy::none())
        .https_only(true).http1_only().no_gzip().no_brotli().no_zstd().no_deflate()
        .pool_max_idle_per_host(0).timeout(HTTPS_LIMIT).connect_timeout(Duration::from_secs(3)).build()
    {
        Ok(client) => client,
        Err(_) => { result.https = State::Unknown; result.https_reason = Reason::Internal; return result; }
    };
    let mut headers_received = false;
    let response = timeout(HTTPS_LIMIT, async {
        let mut response = client.get(url).header(primp::header::ACCEPT_ENCODING, "identity")
            .send().await.map_err(|_| Reason::TransportError)?;
        headers_received = true;
        if !response.status().is_success() { return Ok((State::EndpointError, Reason::HttpStatus)); }
        if response.content_length().is_some_and(|length| length > MAX_BODY as u64) {
            return Ok((State::EndpointError, Reason::BodyLimit));
        }
        let mut bytes = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| Reason::BodyError)? {
            bytes = bytes.saturating_add(chunk.len());
            if bytes > MAX_BODY { return Ok((State::EndpointError, Reason::BodyLimit)); }
        }
        Ok::<_, Reason>((State::Ok, Reason::None))
    }).await;
    result.reachable = headers_received;
    let (state, reason) = match response {
        Ok(Ok(value)) => value,
        Ok(Err(reason)) if headers_received => (State::EndpointError, reason),
        Ok(Err(reason)) => (State::Fail, reason),
        Err(_) if headers_received => (State::EndpointError, Reason::Timeout),
        Err(_) => (State::Fail, Reason::Timeout),
    };
    result.state = state; result.https = state; result.https_reason = reason;
    result
}

fn query_packet(name: &str, id: u16) -> Result<Vec<u8>, Reason> {
    if name.is_empty() || name.len() > 253 { return Err(Reason::InvalidReply); }
    let mut packet = vec![0u8; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1; packet[5] = 1;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err(Reason::InvalidReply);
        }
        packet.push(label.len() as u8); packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(packet)
}

async fn dns_query(source: Ipv4Addr, server: SocketAddr, name: &str, tcp: bool) -> Result<Vec<Ipv4Addr>, Reason> {
    let id = rand::random::<u16>();
    let packet = query_packet(name, id)?;
    timeout(DNS_LIMIT, async {
        let reply = dns_exchange(source, server, &packet, tcp).await?;
        match parse_reply(&reply, name, id) {
            Err(Reason::Truncated) if !tcp => {
                let reply = dns_exchange(source, server, &packet, true).await?;
                parse_reply(&reply, name, id)
            }
            result => result,
        }
    }).await.map_err(|_| Reason::Timeout)?
}

async fn dns_exchange(source: Ipv4Addr, server: SocketAddr, packet: &[u8], tcp: bool) -> Result<Vec<u8>, Reason> {
    if tcp {
        let socket = TcpSocket::new_v4().map_err(|_| Reason::TransportError)?;
        #[cfg(target_os = "linux")]
        if source == VPN_SOURCE { bind_device(&socket, b"csqtt0\0")?; }
        socket.bind(SocketAddr::from((source, 0))).map_err(|_| Reason::TransportError)?;
        let mut stream = socket.connect(server).await.map_err(|_| Reason::TransportError)?;
        stream.write_all(&(packet.len() as u16).to_be_bytes()).await.map_err(|_| Reason::TransportError)?;
        stream.write_all(packet).await.map_err(|_| Reason::TransportError)?;
        let mut length = [0; 2];
        stream.read_exact(&mut length).await.map_err(|_| Reason::TransportError)?;
        let length = u16::from_be_bytes(length) as usize;
        if !(12..=MAX_DNS).contains(&length) { return Err(Reason::InvalidReply); }
        let mut reply = vec![0; length];
        stream.read_exact(&mut reply).await.map_err(|_| Reason::TransportError)?;
        Ok(reply)
    } else {
        let socket = UdpSocket::bind((source, 0)).await.map_err(|_| Reason::TransportError)?;
        #[cfg(target_os = "linux")]
        if source == VPN_SOURCE { bind_device(&socket, b"csqtt0\0")?; }
        socket.connect(server).await.map_err(|_| Reason::TransportError)?;
        let sent = socket.send(packet).await.map_err(|_| Reason::TransportError)?;
        if sent != packet.len() { return Err(Reason::TransportError); }
        let mut reply = vec![0; MAX_DNS + 1];
        let length = socket.recv(&mut reply).await.map_err(|_| Reason::TransportError)?;
        if length > MAX_DNS { return Err(Reason::InvalidReply); }
        reply.truncate(length); Ok(reply)
    }
}

#[cfg(target_os = "linux")]
fn bind_device(socket: &impl std::os::fd::AsRawFd, device: &[u8]) -> Result<(), Reason> {
    // Source routing alone can disappear during explicit policy deactivation.
    // A socket pinned to the TUN cannot migrate to WAN when guards are removed.
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET,
        libc::SO_BINDTODEVICE, device.as_ptr().cast(), device.len() as libc::socklen_t) };
    if result == 0 { Ok(()) } else { Err(Reason::TransportError) }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, Reason> {
    let value = packet.get(offset..offset.checked_add(2).ok_or(Reason::InvalidReply)?).ok_or(Reason::InvalidReply)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize), Reason> {
    let mut position = offset;
    let mut next = None;
    let mut name = String::new();
    let mut jumps = 0;
    loop {
        let length = *packet.get(position).ok_or(Reason::InvalidReply)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(position + 1).ok_or(Reason::InvalidReply)?;
            let pointer = (((length & 0x3f) as usize) << 8) | low as usize;
            // RFC compression refers to an earlier occurrence. Backward-only
            // pointers plus a bound exclude loops and pathological chains.
            if pointer < 12 || pointer >= position || jumps >= 32 { return Err(Reason::InvalidReply); }
            next.get_or_insert(position + 2); position = pointer; jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 { return Err(Reason::InvalidReply); }
        position += 1;
        if length == 0 { return Ok((name, next.unwrap_or(position))); }
        let label = packet.get(position..position + length as usize).ok_or(Reason::InvalidReply)?;
        if !label.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_') { return Err(Reason::InvalidReply); }
        if !name.is_empty() { name.push('.'); }
        for byte in label { name.push(byte.to_ascii_lowercase() as char); }
        if name.len() > 253 { return Err(Reason::InvalidReply); }
        position += length as usize;
    }
}

fn parse_reply(packet: &[u8], name: &str, id: u16) -> Result<Vec<Ipv4Addr>, Reason> {
    if packet.len() < 12 || packet.len() > MAX_DNS || read_u16(packet, 0)? != id { return Err(Reason::InvalidReply); }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || read_u16(packet, 4)? != 1 { return Err(Reason::InvalidReply); }
    let (question, mut offset) = read_name(packet, 12)?;
    if question != name || read_u16(packet, offset)? != 1 || read_u16(packet, offset + 2)? != 1 { return Err(Reason::InvalidReply); }
    offset += 4;
    if flags & 0x0200 != 0 { return Err(Reason::Truncated); }
    if flags & 0x000f != 0 { return Err(Reason::Rejected); }
    let answers = read_u16(packet, 6)? as usize;
    let count = answers + read_u16(packet, 8)? as usize + read_u16(packet, 10)? as usize;
    if count > 128 { return Err(Reason::InvalidReply); }
    let mut addresses = Vec::new();
    let mut aliases = Vec::new();
    for index in 0..count {
        let (owner, next) = read_name(packet, offset)?; offset = next;
        let kind = read_u16(packet, offset)?;
        let class = read_u16(packet, offset + 2)?;
        let length = read_u16(packet, offset + 8)? as usize;
        offset = offset.checked_add(10).ok_or(Reason::InvalidReply)?;
        let end = offset.checked_add(length).ok_or(Reason::InvalidReply)?;
        let data = packet.get(offset..end).ok_or(Reason::InvalidReply)?;
        if class == 1 && kind == 1 {
            if length != 4 { return Err(Reason::InvalidReply); }
            if index < answers { addresses.push((owner, Ipv4Addr::new(data[0], data[1], data[2], data[3]))); }
        } else if class == 1 && kind == 5 {
            let (alias, consumed) = read_name(packet, offset)?;
            if consumed != end || alias.is_empty() { return Err(Reason::InvalidReply); }
            if index < answers { aliases.push((owner, alias)); }
        }
        offset = end;
    }
    if offset != packet.len() { return Err(Reason::InvalidReply); }
    let mut current = name.to_owned();
    let mut seen = Vec::new();
    for _ in 0..=16 {
        if seen.contains(&current) { return Err(Reason::InvalidReply); }
        seen.push(current.clone());
        let result: Vec<_> = addresses.iter().filter(|(owner, ip)| owner == &current && unicast(*ip))
            .map(|(_, ip)| *ip).collect();
        if !result.is_empty() { return Ok(result); }
        let matching: Vec<_> = aliases.iter().filter(|(owner, _)| owner == &current).collect();
        if matching.len() != 1 { return Err(Reason::NoAnswers); }
        current = matching[0].1.clone();
    }
    Err(Reason::InvalidReply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn answer(query: &[u8]) -> Vec<u8> {
        let mut packet = query.to_vec();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        packet
    }

    #[test]
    fn input_is_bounded_and_never_allows_vpn_to_unbind() {
        let good = br#"{"source_ipv4":"198.18.0.1","dns_ipv4":"1.1.1.1","group_ports":[5400,5415]}"#;
        assert!(parse_input(Mode::Vpn, good).is_some());
        assert!(parse_input(Mode::Wan, good).is_none());
        for bad in [
            br#"{"source_ipv4":"0.0.0.0","dns_ipv4":"1.1.1.1"}"#.as_slice(),
            br#"{"source_ipv4":"192.0.2.1","dns_ipv4":"1.1.1.1","mode":"vpn"}"#,
            br#"{"source_ipv4":"198.18.0.1","dns_ipv4":"1.1.1.1","group_ports":[5400,5400]}"#,
            br#"{"source_ipv4":"198.18.0.1","dns_ipv4":"1.1.1.1","group_ports":[53]}"#,
            br#"{"source_ipv4":"198.18.0.1","dns_ipv4":"1.1.1.1","unknown":"private"}"#,
        ] { assert!(parse_input(Mode::Vpn, bad).is_none()); }
        assert!(parse_input(Mode::Vpn, &vec![b' '; MAX_INPUT + 1]).is_none());
    }

    #[test]
    fn exact_dns_answer_and_question_are_required() {
        let query = query_packet("example.com", 1234).unwrap();
        let good = answer(&query);
        assert_eq!(parse_reply(&good, "example.com", 1234).unwrap(), vec![Ipv4Addr::new(192, 0, 2, 1)]);
        for length in 0..good.len() { assert!(parse_reply(&good[..length], "example.com", 1234).is_err()); }
        for offset in [0, 5, 13, good.len() - 5] {
            let mut bad = good.clone(); bad[offset] ^= 1;
            assert!(parse_reply(&bad, "example.com", 1234).is_err());
        }
        let mut not_a_response = good.clone(); not_a_response[2] &= 0x7f;
        assert_eq!(parse_reply(&not_a_response, "example.com", 1234), Err(Reason::InvalidReply));
        let mut extra = good.clone(); extra.push(0);
        assert_eq!(parse_reply(&extra, "example.com", 1234), Err(Reason::InvalidReply));
        let mut unrelated = good; unrelated[query.len() + 1] = 13;
        assert!(parse_reply(&unrelated, "example.com", 1234).is_err());
    }

    #[test]
    fn dns_pointer_cycles_forward_pointers_and_bad_lengths_are_rejected() {
        for name in [vec![0xc0, 12], vec![0xc0, 14, 0], vec![0x40, 0], vec![63, b'a']] {
            let mut packet = vec![0; 12]; packet.extend_from_slice(&name);
            assert!(read_name(&packet, 12).is_err());
        }
        let mut packet = answer(&query_packet("example.com", 1).unwrap());
        packet[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_reply(&packet, "example.com", 1).is_err());
    }

    #[test]
    fn cname_answers_are_followed_only_from_the_requested_name() {
        let query = query_packet("example.com", 9).unwrap();
        let mut packet = query.clone();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&2u16.to_be_bytes());
        // example.com CNAME alias.example.com, using the earlier suffix.
        packet.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 8]);
        let alias_offset = packet.len();
        packet.extend_from_slice(&[5, b'a', b'l', b'i', b'a', b's', 0xc0, 12]);
        packet.extend_from_slice(&[0xc0, alias_offset as u8, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 9]);
        assert_eq!(parse_reply(&packet, "example.com", 9).unwrap(), vec![Ipv4Addr::new(192, 0, 2, 9)]);
        // The same A answer in an unrelated response is never accepted.
        assert!(parse_reply(&packet, "different.example.com", 9).is_err());
    }

    #[test]
    fn dns_rejection_empty_answers_and_truncation_have_distinct_results() {
        let query = query_packet("example.com", 1).unwrap();
        let mut packet = query;
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        assert_eq!(parse_reply(&packet, "example.com", 1), Err(Reason::NoAnswers));
        packet[3] |= 3;
        assert_eq!(parse_reply(&packet, "example.com", 1), Err(Reason::Rejected));
        packet[2] |= 2;
        assert_eq!(parse_reply(&packet, "example.com", 1), Err(Reason::Truncated));
    }

    #[test]
    fn malformed_dns_fuzz_is_bounded_and_never_panics() {
        let mut seed = 0x5a7d_9e01u32;
        for length in 0..1024 {
            let mut packet = vec![0; length];
            for byte in &mut packet { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; *byte = seed as u8; }
            let _ = parse_reply(&packet, "example.com", 7);
            if length > 12 { let _ = read_name(&packet, 12); }
        }
    }

    #[tokio::test]
    async fn udp_and_tcp_dns_use_the_explicit_source_and_validate_the_reply() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(server).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buffer = [0; 512]; let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            udp.send_to(&answer(&buffer[..length]), peer).await.unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, peer) = tcp.accept().await.unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut length = [0; 2]; stream.read_exact(&mut length).await.unwrap();
            let mut query = vec![0; u16::from_be_bytes(length) as usize]; stream.read_exact(&mut query).await.unwrap();
            let reply = answer(&query);
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap(); stream.write_all(&reply).await.unwrap();
        });
        assert!(dns_query(Ipv4Addr::LOCALHOST, server, "example.com", false).await.is_ok());
        assert!(dns_query(Ipv4Addr::LOCALHOST, server, "example.com", true).await.is_ok());
        udp_task.await.unwrap(); tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_udp_retries_tcp_without_changing_source_or_resolver() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server = udp.local_addr().unwrap(); let tcp = TcpListener::bind(server).await.unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 512]; let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let mut truncated = buffer[..length].to_vec(); truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
            udp.send_to(&truncated, peer).await.unwrap();
            let (mut stream, tcp_peer) = tcp.accept().await.unwrap(); assert_eq!(peer.ip(), tcp_peer.ip());
            let mut length = [0; 2]; stream.read_exact(&mut length).await.unwrap();
            let mut query = vec![0; u16::from_be_bytes(length) as usize]; stream.read_exact(&mut query).await.unwrap();
            let reply = answer(&query); stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap(); stream.write_all(&reply).await.unwrap();
        });
        assert!(dns_query(Ipv4Addr::LOCALHOST, server, "example.com", false).await.is_ok()); task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn missing_dns_answer_is_a_bounded_failure() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = server.local_addr().unwrap();
        let result = dns_query(Ipv4Addr::LOCALHOST, address, "example.com", false).await;
        assert_eq!(result, Err(Reason::Timeout));
    }

    #[tokio::test]
    async fn invalid_tcp_frame_length_is_rejected_before_allocation() {
        for length in [0u16, 11, (MAX_DNS + 1) as u16] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(); let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut prefix = [0; 2]; stream.read_exact(&mut prefix).await.unwrap();
                let mut query = vec![0; u16::from_be_bytes(prefix) as usize]; stream.read_exact(&mut query).await.unwrap();
                stream.write_all(&length.to_be_bytes()).await.unwrap();
            });
            assert_eq!(dns_query(Ipv4Addr::LOCALHOST, address, "example.com", true).await, Err(Reason::InvalidReply)); task.await.unwrap();
        }
    }

    #[test]
    fn reachable_endpoint_errors_prevent_false_path_outage_and_output_is_redacted() {
        let mut value = Observation::empty(Some(Mode::Vpn));
        for result in &mut value.endpoints { result.state = State::Fail; result.dns = State::Ok; result.https = State::Fail; }
        value.aggregate(); assert_eq!(value.path, State::Fail);
        value.endpoints[0].state = State::EndpointError; value.endpoints[0].reachable = true;
        value.aggregate(); assert_eq!(value.path, State::EndpointError);
        let json = serde_json::to_string(&value).unwrap();
        for hidden in ["198.18", "cloudflare", "dns.google", "example.com", "http://", "https://", "password", "identity"] { assert!(!json.contains(hidden)); }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn missing_bound_interface_fails_without_falling_back() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        assert_eq!(bind_device(&socket, b"cq-no-probe\0"), Err(Reason::TransportError));
        let tcp = TcpSocket::new_v4().unwrap();
        assert_eq!(bind_device(&tcp, b"cq-no-probe\0"), Err(Reason::TransportError));
    }
}
