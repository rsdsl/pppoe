use crate::config::Config;
use crate::error::{Error, Result};

use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use byteorder::{ByteOrder, NetworkEndian as NE};

use pppoe::chap;
use pppoe::eth;
use pppoe::header::{PADO, PADS, PADT, PPP};
use pppoe::ipcp;
use pppoe::lcp;
use pppoe::packet::{PPPOE_DISCOVERY, PPPOE_SESSION};
use pppoe::ppp::{self, Protocol, CHAP, IPCP, IPV4, LCP};
use pppoe::Header;
use pppoe::HeaderBuilder;
use pppoe::Packet;
use pppoe::Socket;
use pppoe::Tag;
use rsdsl_ip_config::IpConfig;

const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const BUFSIZE: usize = 1522;

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Idle,
    Discovery,
    Requesting,
    Session(NonZeroU16),
    Terminated,
}

impl Default for State {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: Arc<RwLock<ClientRef>>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self> {
        let link = config.link.clone();

        Ok(Self {
            inner: Arc::new(RwLock::new(ClientRef {
                config,
                socket: Socket::on_interface(&link)?,
                started: false,
                host_uniq: rand::random(),
                state: State::default(),
                peer: BROADCAST,
                magic_number: rand::random(),
                error: String::new(),
                ip_config: IpConfig::default(),
            })),
        })
    }

    pub fn run(
        self,
        ip_tx: mpsc::Sender<Vec<u8>>,
        ipchange_tx: mpsc::Sender<IpConfig>,
    ) -> Result<()> {
        if !self.inner.read().unwrap().started {
            let clt = self.clone();
            let handle = thread::spawn(move || clt.recv_loop(ip_tx, ipchange_tx));

            self.discover()?;

            Ok(handle.join().unwrap()?)
        } else {
            Err(Error::AlreadyActive)
        }
    }

    fn terminate(&self, why: Result<()>) {
        let why_fmt = format!("{:?}", why);

        let reason = if let Err(e) = why {
            format!("{:?}", e)
        } else {
            String::new()
        };

        let limit = reason.len();

        let mut request = Vec::new();
        request.resize(14 + 6 + 2 + 4 + limit, 0);

        let request = request.as_mut_slice();
        request[26..26 + limit].copy_from_slice(reason.as_bytes());

        if lcp::HeaderBuilder::create_terminate_request(&mut request[22..26 + limit]).is_ok()
            && self.new_lcp_packet(request).is_ok()
        {
            self.send(request).ok();
        }

        let mut padt = Vec::new();
        padt.resize(14 + 6 + 4 + reason.len(), 0);

        if let Ok(session_id) = self.session_id() {
            let padt = padt.as_mut_slice();
            if let Ok(mut padt_header) = HeaderBuilder::create_padt(&mut padt[14..], session_id) {
                padt_header
                    .add_tag(Tag::GenericError(reason.as_bytes()))
                    .ok();

                if self.new_discovery_packet(padt).is_ok() {
                    self.send(padt).ok();
                }
            }
        }

        self.inner.write().unwrap().error = why_fmt;
        self.set_state(State::Terminated);
    }

    fn why_terminated(&self) -> String {
        self.inner.read().unwrap().error.clone()
    }

    fn state(&self) -> State {
        self.inner.read().unwrap().state
    }

    fn set_state(&self, state: State) {
        self.inner.write().unwrap().state = state;
    }

    fn session_id(&self) -> Result<NonZeroU16> {
        match self.state() {
            State::Session(session_id) => Ok(session_id),
            _ => Err(Error::NoSession),
        }
    }

    fn peer(&self) -> [u8; 6] {
        self.inner.read().unwrap().peer
    }

    fn set_peer(&self, peer: [u8; 6]) {
        self.inner.write().unwrap().peer = peer;
    }

    fn magic_number(&self) -> u32 {
        self.inner.read().unwrap().magic_number
    }

    pub fn ip_config(&self) -> IpConfig {
        self.inner.read().unwrap().ip_config
    }

    fn set_ip_config(&self, ip_config: IpConfig) {
        self.inner.write().unwrap().ip_config = ip_config;
    }

    fn new_discovery_packet(&self, buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.read().unwrap().socket.mac_address();

        let mut ethernet_header = eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(self.peer());
        ethernet_header.set_ether_type(PPPOE_DISCOVERY);

        Ok(())
    }

    fn new_session_packet(&self, buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.read().unwrap().socket.mac_address();

        let mut ethernet_header = eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(self.peer());
        ethernet_header.set_ether_type(PPPOE_SESSION);

        Ok(())
    }

    fn new_ppp_packet(&self, protocol: Protocol, buf: &mut [u8]) -> Result<()> {
        ppp::HeaderBuilder::create_packet(&mut buf[20..], protocol)?;

        let session_id = self.session_id()?;
        HeaderBuilder::create_ppp(&mut buf[14..], session_id)?;

        self.new_session_packet(buf)?;

        Ok(())
    }

    fn new_lcp_packet(&self, buf: &mut [u8]) -> Result<()> {
        self.new_ppp_packet(Protocol::Lcp, buf)
    }

    fn new_chap_packet(&self, buf: &mut [u8]) -> Result<()> {
        self.new_ppp_packet(Protocol::Chap, buf)
    }

    fn new_ipcp_packet(&self, buf: &mut [u8]) -> Result<()> {
        self.new_ppp_packet(Protocol::Ipcp, buf)
    }

    fn new_ipv4_packet(&self, buf: &mut [u8]) -> Result<()> {
        self.new_ppp_packet(Protocol::Ipv4, buf)
    }

    pub fn send_ipv4(&self, buf: &[u8]) -> Result<()> {
        match self.state() {
            State::Session(_) => {}
            _ => return Err(Error::NoSession),
        }

        let mut dgram = Vec::new();
        dgram.resize(14 + 6 + 2 + buf.len(), 0);

        let dgram = dgram.as_mut_slice();
        dgram[22..].copy_from_slice(buf);

        self.new_ipv4_packet(dgram)?;
        self.send(dgram)?;

        Ok(())
    }

    fn send(&self, buf: &[u8]) -> Result<()> {
        let n = self.inner.read().unwrap().socket.send(buf)?;
        if n != buf.len() {
            Err(Error::PartialTransmission)
        } else {
            Ok(())
        }
    }

    fn send_while_state(&self, buf: &[u8], state: State, max: Option<u8>, msg: impl Into<String>) {
        let this = self.clone();
        let buf = buf.to_vec();
        let msg = msg.into();

        thread::spawn(move || {
            let mut i = 0;
            while this.state() == state {
                if let Some(max) = max {
                    if i >= max {
                        continue;
                    }
                }

                match this.send(&buf) {
                    Ok(_) => println!("(re)transmission: {}", &msg),
                    Err(e) => println!("(re)transmission failed: {}", e),
                }

                thread::sleep(Duration::from_secs(3));
                i += 1
            }
        });
    }

    fn recv<'a>(&'a self, buf: &'a mut [u8; BUFSIZE]) -> Result<Packet> {
        let mut n;

        loop {
            n = self.recv_pkt(buf)?;
            let buf = &buf[..n];

            let pkt = Packet::with_buffer(buf)?;
            let eth = pkt.ethernet_header();
            let header = pkt.pppoe_header();

            // from correct peer MAC?
            if self.peer() != BROADCAST && eth.src_address() != self.peer() {
                continue;
            }

            // correct session id?
            if header.code() != PADS
                && header.session_id() != self.session_id().map(|id| id.into()).unwrap_or(0)
            {
                continue;
            }

            break;
        }

        Ok(Packet::with_buffer(&buf[..n])?)
    }

    fn recv_pkt(&self, buf: &mut [u8; BUFSIZE]) -> Result<usize> {
        let n = self.inner.read().unwrap().socket.recv(buf)?;
        Ok(n)
    }

    fn discover(&self) -> Result<()> {
        if self.state() != State::Idle {
            return Err(Error::AlreadyActive);
        }

        let host_uniq = self.inner.read().unwrap().host_uniq;

        let mut discovery = [0; 14 + 6 + 4 + 20];
        let mut discovery_header = HeaderBuilder::create_padi(&mut discovery[14..])?;

        discovery_header.add_tag(Tag::ServiceName(b""))?;
        discovery_header.add_tag(Tag::HostUniq(&host_uniq))?;

        self.set_state(State::Discovery);

        self.new_discovery_packet(&mut discovery)?;
        self.send_while_state(&discovery, State::Discovery, None, "PADI");

        println!("discovering...");
        Ok(())
    }

    fn configure_link(&self) -> Result<()> {
        match self.state() {
            State::Session(_) => {}
            _ => return Err(Error::NoSession),
        }

        let mut opts = lcp::ConfigOptions::default();

        opts.add_option(lcp::ConfigOption::Mru(1452));
        opts.add_option(lcp::ConfigOption::MagicNumber(self.magic_number()));

        let limit = opts.len();

        let mut request = Vec::new();
        request.resize(14 + 6 + 2 + 4 + limit, 0);

        let request = request.as_mut_slice();
        opts.write_to_buffer(&mut request[26..26 + limit])?;

        lcp::HeaderBuilder::create_configure_request(&mut request[22..26 + limit])?;

        self.new_lcp_packet(request)?;
        self.send(request)?;

        println!("requested LCP configuration");
        Ok(())
    }

    fn configure_ip(&self) -> Result<()> {
        match self.state() {
            State::Session(_) => {}
            _ => return Err(Error::NoSession),
        }

        let all_zero = Ipv4Addr::new(0, 0, 0, 0);

        let mut opts = ipcp::ConfigOptions::default();

        opts.add_option(ipcp::ConfigOption::IpAddress(all_zero));
        opts.add_option(ipcp::ConfigOption::PrimaryDns(all_zero));
        opts.add_option(ipcp::ConfigOption::SecondaryDns(all_zero));

        let limit = opts.len();

        let mut request = Vec::new();
        request.resize(14 + 6 + 2 + 4 + limit, 0);

        let request = request.as_mut_slice();
        opts.write_to_buffer(&mut request[26..26 + limit])?;

        ipcp::HeaderBuilder::create_configure_request(&mut request[22..26 + limit])?;

        self.new_ipcp_packet(request)?;
        self.send(request)?;

        println!("requested IPCP configuration");
        Ok(())
    }

    fn handle_ppp(
        &self,
        header: &Header,
        ip_tx: &mpsc::Sender<Vec<u8>>,
        ipchange_tx: &mpsc::Sender<IpConfig>,
    ) -> Result<()> {
        let ppp = ppp::Header::with_buffer(header.payload())?;
        let protocol = ppp.protocol();

        match protocol {
            LCP => self.handle_lcp(ppp),
            CHAP => self.handle_chap(ppp),
            IPCP => self.handle_ipcp(ppp, ipchange_tx),
            IPV4 => self.handle_ipv4(ppp, ip_tx),
            _ => Err(Error::InvalidProtocol(protocol)),
        }
    }

    fn handle_lcp(&self, header: ppp::Header) -> Result<()> {
        let lcp = lcp::Header::with_buffer(header.payload())?;
        let lcp_code = lcp.code();

        match lcp_code {
            lcp::CONFIGURE_REQUEST => {
                let opts: Vec<lcp::ConfigOption> =
                    lcp::ConfigOptionIterator::new(lcp.payload()).collect();

                println!("received LCP configuration request, options: {:?}", opts);

                let limit = lcp.payload().len();

                let mut ack = Vec::new();
                ack.resize(14 + 6 + 2 + 4 + limit, 0);

                let ack = ack.as_mut_slice();
                ack[26..26 + limit].copy_from_slice(lcp.payload());

                lcp::HeaderBuilder::create_configure_ack(
                    &mut ack[22..26 + limit],
                    lcp.identifier(),
                )?;

                self.new_lcp_packet(ack)?;
                self.send(ack)?;

                println!(
                    "acknowledged LCP configuration request, options: {:?}",
                    opts
                );
                Ok(())
            }
            lcp::CONFIGURE_ACK => {
                let opts: Vec<lcp::ConfigOption> =
                    lcp::ConfigOptionIterator::new(lcp.payload()).collect();

                if opts.len() != 2
                    || opts[0] != lcp::ConfigOption::Mru(1452)
                    || opts[1] != lcp::ConfigOption::MagicNumber(self.magic_number())
                {
                    return Err(Error::AckedWrongOptions);
                }

                println!(
                    "link configuration acknowledged by peer, options: {:?}",
                    opts
                );
                Ok(())
            }
            lcp::CONFIGURE_NAK => {
                let opts: Vec<lcp::ConfigOption> =
                    lcp::ConfigOptionIterator::new(lcp.payload()).collect();

                println!(
                    "the following LCP configuration options were not acknowledged: {:?}",
                    opts
                );

                self.terminate(Err(Error::ConfigNak));
                Ok(())
            }
            lcp::CONFIGURE_REJECT => {
                let opts: Vec<lcp::ConfigOption> =
                    lcp::ConfigOptionIterator::new(lcp.payload()).collect();

                println!(
                    "the following LCP configuration options were rejected: {:?}",
                    opts
                );

                self.terminate(Err(Error::ConfigReject));
                Ok(())
            }
            lcp::ECHO_REQUEST => {
                let limit = lcp.payload().len();

                let mut reply = [0; 14 + 6 + 2 + 4 + 4];
                NE::write_u32(&mut reply[26..30], self.magic_number());

                lcp::HeaderBuilder::create_echo_reply(
                    &mut reply[22..26 + limit],
                    lcp.identifier(),
                )?;

                self.new_lcp_packet(&mut reply)?;
                self.send(&reply)?;

                println!("replied to LCP ping");
                Ok(())
            }
            lcp::TERMINATE_REQUEST => {
                let reason = String::from_utf8(lcp.payload().to_vec())?;

                let mut ack = [0; 14 + 6 + 2 + 4];

                lcp::HeaderBuilder::create_terminate_ack(&mut ack[22..26], lcp.identifier())?;

                self.new_lcp_packet(&mut ack)?;
                self.send(&ack)?;

                self.set_state(State::Terminated);

                println!("acknowledged LCP termination request, reason: {}", reason);
                Ok(())
            }
            lcp::TERMINATE_ACK => {
                // Peer is in a state that requires re-negotiation / re-connection
                // but it hasn't informed us properly.
                // This code should never run if the termination was requested by us.

                self.inner.write().unwrap().error = format!("{:?}", Error::UnexpectedTermAck);
                self.set_state(State::Terminated);

                println!("peer acknowledged unrequested link termination");
                Ok(())
            }
            _ => Err(Error::InvalidLcpCode(lcp_code)),
        }
    }

    fn handle_chap(&self, header: ppp::Header) -> Result<()> {
        let chap = chap::Header::with_buffer(header.payload())?;
        let chap_code = chap.code();

        match chap_code {
            chap::CHALLENGE => {
                let config = &self.inner.read().unwrap().config;
                let username = config.username.as_bytes();
                let password = config.password.as_bytes();

                let limit = 1 + chap.payload()[0];
                let challenge = &chap.payload()[1..limit as usize];

                let mut chap_input = Vec::new();

                chap_input.push(chap.identifier());
                chap_input.extend_from_slice(password);
                chap_input.extend_from_slice(challenge);

                let chap_response = *md5::compute(chap_input);

                let mut response = Vec::new();
                response.resize(14 + 6 + 2 + 4 + 1 + 16 + username.len(), 0);

                let response = response.as_mut_slice();
                response[26] = 16; // constant length
                response[27..27 + 16].copy_from_slice(&chap_response);
                response[27 + 16..].copy_from_slice(username);

                chap::HeaderBuilder::create_response(&mut response[22..], chap.identifier())?;

                self.new_chap_packet(response)?;
                self.send(response)?;

                println!("solved CHAP-MD5 challenge");
                Ok(())
            }
            chap::SUCCESS => {
                println!("authentication succeeded");

                self.configure_ip()?;
                Ok(())
            }
            chap::FAILURE => {
                println!("authentication failed");
                Ok(())
            }
            _ => Err(Error::InvalidChapCode(chap_code)),
        }
    }

    fn handle_ipcp(&self, header: ppp::Header, tx: &mpsc::Sender<IpConfig>) -> Result<()> {
        let ipcp = ipcp::Header::with_buffer(header.payload())?;
        let ipcp_code = ipcp.code();

        match ipcp_code {
            ipcp::CONFIGURE_REQUEST => {
                let opts: Vec<ipcp::ConfigOption> =
                    ipcp::ConfigOptionIterator::new(ipcp.payload()).collect();

                println!("received IPCP configuration request, options: {:?}", opts);

                let mut ip_config = self.ip_config();

                ip_config.rtr = *opts
                    .iter()
                    .find_map(|opt| {
                        if let ipcp::ConfigOption::IpAddress(addr) = opt {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::MissingIpAddr)?;

                self.set_ip_config(ip_config);
                tx.send(ip_config)?;

                let limit = ipcp.payload().len();

                let mut ack = Vec::new();
                ack.resize(14 + 6 + 2 + 4 + limit, 0);

                let ack = ack.as_mut_slice();
                ack[26..26 + limit].copy_from_slice(ipcp.payload());

                ipcp::HeaderBuilder::create_configure_ack(
                    &mut ack[22..26 + limit],
                    ipcp.identifier(),
                )?;

                self.new_ipcp_packet(ack)?;
                self.send(ack)?;

                println!(
                    "ackknowledged IPCP configuration request, options: {:?}",
                    opts
                );

                Ok(())
            }
            ipcp::CONFIGURE_ACK => {
                let opts: Vec<ipcp::ConfigOption> =
                    ipcp::ConfigOptionIterator::new(ipcp.payload()).collect();

                let mut ip_config = self.ip_config();

                ip_config.addr = *opts
                    .iter()
                    .find_map(|opt| {
                        if let ipcp::ConfigOption::IpAddress(addr) = opt {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::MissingIpAddr)?;

                ip_config.dns1 = *opts
                    .iter()
                    .find_map(|opt| {
                        if let ipcp::ConfigOption::PrimaryDns(addr) = opt {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::MissingPrimaryDns)?;

                ip_config.dns2 = *opts
                    .iter()
                    .find_map(|opt| {
                        if let ipcp::ConfigOption::SecondaryDns(addr) = opt {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .ok_or(Error::MissingSecondaryDns)?;

                self.set_ip_config(ip_config);
                tx.send(ip_config)?;

                println!("ip configuration acknowledged by peer, options: {:?}", opts);
                println!(
                    "ip session opened, addr={}, rtr={}, dns1={}, dns2={}",
                    ip_config.addr, ip_config.rtr, ip_config.dns1, ip_config.dns2
                );
                Ok(())
            }
            ipcp::CONFIGURE_NAK => {
                let opts: Vec<ipcp::ConfigOption> =
                    ipcp::ConfigOptionIterator::new(ipcp.payload()).collect();

                println!("obtained configuration via IPCP NAK: {:?}", opts);

                let limit = ipcp.payload().len();

                let mut request = Vec::new();
                request.resize(14 + 6 + 2 + 4 + limit, 0);

                let request = request.as_mut_slice();
                request[26..26 + limit].copy_from_slice(ipcp.payload());

                ipcp::HeaderBuilder::create_configure_request(&mut request[22..26 + limit])?;

                self.new_ipcp_packet(request)?;
                self.send(request)?;

                println!("verifying configuration via IPCP request");
                Ok(())
            }
            ipcp::CONFIGURE_REJECT => {
                let opts: Vec<ipcp::ConfigOption> =
                    ipcp::ConfigOptionIterator::new(ipcp.payload()).collect();

                println!(
                    "the following IPCP configuration options were rejected: {:?}",
                    opts
                );

                self.terminate(Err(Error::ConfigReject));
                Ok(())
            }
            _ => Err(Error::InvalidIpcpCode(ipcp_code)),
        }
    }

    fn handle_ipv4(&self, header: ppp::Header, ip_tx: &mpsc::Sender<Vec<u8>>) -> Result<()> {
        let ipv4 = header.payload();
        ip_tx.send(ipv4.to_vec())?;

        Ok(())
    }

    fn recv_loop(
        &self,
        ip_tx: mpsc::Sender<Vec<u8>>,
        ipchange_tx: mpsc::Sender<IpConfig>,
    ) -> Result<()> {
        loop {
            let mut buf = [0; BUFSIZE];

            let pkt = self.recv(&mut buf)?;
            let header = pkt.pppoe_header();
            let code = header.code();

            let remote_mac = pkt.ethernet_header().src_address();
            let remote_mac_str = remote_mac
                .iter()
                .map(|octet| format!("{:02x}", octet))
                .reduce(|acc, octet| acc + ":" + &octet)
                .unwrap();

            match match code {
                PPP => {
                    if let State::Session(_) = self.state() {
                        self.handle_ppp(header, &ip_tx, &ipchange_tx)
                    } else {
                        Err(Error::UnexpectedPpp)
                    }
                }
                PADO => {
                    let ac_name = header
                        .tags()
                        .find_map(|tag| {
                            if let Tag::AcName(ac_name) = tag {
                                String::from_utf8(ac_name.to_vec()).ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(String::new());

                    let ac_cookie = header.tags().find_map(|tag| {
                        if let Tag::AcCookie(ac_cookie) = tag {
                            Some(ac_cookie)
                        } else {
                            None
                        }
                    });

                    if self.state() == State::Discovery {
                        println!(
                            "accepting offer from MAC {}, AC {}",
                            remote_mac_str, ac_name
                        );

                        self.set_peer(remote_mac);

                        let mut request = [0; 14 + 6 + 4 + 24];
                        let mut request_header = HeaderBuilder::create_padr(&mut request[14..])?;

                        request_header.add_tag(Tag::ServiceName(b""))?;

                        if let Some(ac_cookie) = ac_cookie {
                            request_header.add_tag(Tag::AcCookie(ac_cookie))?;
                        }

                        self.set_state(State::Requesting);

                        self.new_discovery_packet(&mut request)?;
                        self.send_while_state(&request, State::Requesting, Some(10), "PADR");

                        println!("requesting...");
                    } else {
                        println!("ignoring offer from MAC {}, AC {}", remote_mac_str, ac_name);
                    }

                    Ok(())
                }
                PADS => {
                    if self.state() == State::Requesting {
                        let session_id =
                            NonZeroU16::new(header.session_id()).ok_or(Error::ZeroSession)?;

                        self.set_state(State::Session(session_id));
                        println!("session established, ID {}", session_id);

                        thread::sleep(Duration::from_secs(1));
                        self.configure_link()?;

                        Ok(())
                    } else {
                        Err(Error::UnexpectedPads)
                    }
                }
                PADT => {
                    self.set_state(State::Terminated);

                    self.inner.write().unwrap().socket.close();

                    println!("session terminated by peer (PADT), MAC {}", remote_mac_str);
                    return Ok(());
                }
                _ => Err(Error::InvalidCode(code)),
            } {
                Ok(_) => {}
                Err(e) => println!("error processing packet from MAC {}: {}", remote_mac_str, e),
            }

            if self.state() == State::Terminated {
                self.inner.write().unwrap().socket.close();

                let why = self.why_terminated();
                if why.is_empty() {
                    println!("session closed");
                } else {
                    println!("session closed: {}", why);
                }

                return Ok(());
            }
        }
    }
}

#[derive(Debug)]
struct ClientRef {
    config: Config,
    socket: Socket,
    started: bool,
    host_uniq: [u8; 16],
    state: State,
    peer: [u8; 6],
    magic_number: u32,
    error: String,
    ip_config: IpConfig,
}
