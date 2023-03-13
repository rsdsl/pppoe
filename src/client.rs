use crate::error::{Error, Result};

use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use byteorder::{ByteOrder, NetworkEndian as NE};

use pppoe::chap;
use pppoe::eth;
use pppoe::header::{PADO, PADS, PADT, PPP};
use pppoe::lcp::{
    self, ConfigOption, ConfigOptionIterator, ConfigOptions, CONFIGURE_ACK, CONFIGURE_NAK,
    CONFIGURE_REJECT, CONFIGURE_REQUEST, ECHO_REQUEST, TERMINATE_ACK, TERMINATE_REQUEST,
};
use pppoe::packet::{PPPOE_DISCOVERY, PPPOE_SESSION};
use pppoe::ppp::{self, Protocol, CHAP, LCP};
use pppoe::Header;
use pppoe::HeaderBuilder;
use pppoe::Packet;
use pppoe::Socket;
use pppoe::Tag;

const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

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
    inner: Arc<Mutex<ClientRef>>,
}

impl Client {
    pub fn new(interface: &str) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(ClientRef {
                socket: Socket::on_interface(interface)?,
                started: false,
                host_uniq: rand::random(),
                state: State::default(),
                peer: BROADCAST,
                magic_number: rand::random(),
                error: String::new(),
            })),
        })
    }

    pub fn run(self) -> Result<()> {
        if !self.inner.lock().unwrap().started {
            let clt = self.clone();
            let handle = thread::spawn(move || clt.recv_loop());

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

        self.inner.lock().unwrap().error = why_fmt;
        self.set_state(State::Terminated);
    }

    fn why_terminated(&self) -> String {
        self.inner.lock().unwrap().error.clone()
    }

    fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    fn set_state(&self, state: State) {
        self.inner.lock().unwrap().state = state;
    }

    fn session_id(&self) -> Result<NonZeroU16> {
        match self.state() {
            State::Session(session_id) => Ok(session_id),
            _ => Err(Error::NoSession),
        }
    }

    fn peer(&self) -> [u8; 6] {
        self.inner.lock().unwrap().peer
    }

    fn set_peer(&self, peer: [u8; 6]) {
        self.inner.lock().unwrap().peer = peer;
    }

    fn magic_number(&self) -> u32 {
        self.inner.lock().unwrap().magic_number
    }

    fn new_discovery_packet(&self, buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.lock().unwrap().socket.mac_address();

        let mut ethernet_header = eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(self.peer());
        ethernet_header.set_ether_type(PPPOE_DISCOVERY);

        Ok(())
    }

    fn new_session_packet(&self, buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.lock().unwrap().socket.mac_address();

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

    fn send(&self, buf: &[u8]) -> Result<()> {
        let n = self.inner.lock().unwrap().socket.send(buf)?;
        if n != buf.len() {
            Err(Error::PartialRequest)
        } else {
            Ok(())
        }
    }

    fn recv<'a>(&'a self, buf: &'a mut [u8; 1024]) -> Result<Packet> {
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

    fn recv_pkt(&self, buf: &mut [u8; 1024]) -> Result<usize> {
        let n = self.inner.lock().unwrap().socket.recv(buf)?;
        Ok(n)
    }

    fn discover(&self) -> Result<()> {
        if self.state() != State::Idle {
            return Err(Error::AlreadyActive);
        }

        let host_uniq = self.inner.lock().unwrap().host_uniq;

        let mut discovery = [0; 14 + 6 + 4 + 20];
        let mut discovery_header = HeaderBuilder::create_padi(&mut discovery[14..])?;

        discovery_header.add_tag(Tag::ServiceName(b""))?;
        discovery_header.add_tag(Tag::HostUniq(&host_uniq))?;

        self.new_discovery_packet(&mut discovery)?;
        self.send(&discovery)?;

        self.set_state(State::Discovery);

        println!("sent PADI");
        Ok(())
    }

    fn configure(&self) -> Result<()> {
        match self.state() {
            State::Session(_) => {}
            _ => return Err(Error::AlreadyActive),
        }

        let mut opts = ConfigOptions::default();

        opts.add_option(ConfigOption::Mru(1452));
        opts.add_option(ConfigOption::MagicNumber(self.magic_number()));

        let limit = opts.len();

        let mut request = Vec::new();
        request.resize(14 + 6 + 2 + 4 + limit, 0);

        let request = request.as_mut_slice();
        opts.write_to_buffer(&mut request[26..26 + limit])?;

        lcp::HeaderBuilder::create_configure_request(&mut request[22..26 + limit])?;

        self.new_lcp_packet(request)?;
        self.send(request)?;

        println!("requested configuration");
        Ok(())
    }

    fn handle_ppp(&self, header: &Header) -> Result<()> {
        let ppp = ppp::Header::with_buffer(header.payload())?;
        let protocol = ppp.protocol();

        match protocol {
            LCP => self.handle_lcp(ppp),
            CHAP => self.handle_chap(ppp),
            _ => Err(Error::InvalidProtocol(protocol)),
        }
    }

    fn handle_lcp(&self, header: ppp::Header) -> Result<()> {
        let lcp = lcp::Header::with_buffer(header.payload())?;
        let lcp_code = lcp.code();

        match lcp_code {
            CONFIGURE_REQUEST => {
                let opts: Vec<ConfigOption> = ConfigOptionIterator::new(lcp.payload()).collect();

                println!("received configuration request, options: {:?}", opts);

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

                println!("acknowledged configuration request, options: {:?}", opts);
                Ok(())
            }
            CONFIGURE_ACK => {
                let opts: Vec<ConfigOption> = ConfigOptionIterator::new(lcp.payload()).collect();

                if opts.len() != 2
                    || opts[0] != ConfigOption::Mru(1452)
                    || opts[1] != ConfigOption::MagicNumber(self.magic_number())
                {
                    return Err(Error::AckedWrongOptions);
                }

                println!("configuration acknowledged by peer, options: {:?}", opts);
                Ok(())
            }
            CONFIGURE_NAK => {
                let opts: Vec<ConfigOption> = ConfigOptionIterator::new(lcp.payload()).collect();

                println!(
                    "the following configuration options were not acknowledged: {:?}",
                    opts
                );

                self.terminate(Err(Error::ConfigNak));
                Ok(())
            }
            CONFIGURE_REJECT => {
                let opts: Vec<ConfigOption> = ConfigOptionIterator::new(lcp.payload()).collect();

                println!(
                    "the following configuration options were rejected: {:?}",
                    opts
                );

                self.terminate(Err(Error::ConfigReject));
                Ok(())
            }
            ECHO_REQUEST => {
                let limit = lcp.payload().len();

                let mut reply = [0; 14 + 6 + 2 + 4 + 4];
                NE::write_u32(&mut reply[26..30], self.magic_number());

                lcp::HeaderBuilder::create_echo_reply(
                    &mut reply[22..26 + limit],
                    lcp.identifier(),
                )?;

                self.new_lcp_packet(&mut reply)?;
                self.send(&reply)?;

                println!("replied to ping");
                Ok(())
            }
            TERMINATE_REQUEST => {
                let reason = String::from_utf8(lcp.payload().to_vec())?;

                let mut ack = [0; 14 + 6 + 2 + 4];

                lcp::HeaderBuilder::create_terminate_ack(&mut ack[22..26], lcp.identifier())?;

                self.new_lcp_packet(&mut ack)?;
                self.send(&ack)?;

                self.set_state(State::Terminated);

                println!("acknowledged termination request, reason: {}", reason);
                Ok(())
            }
            TERMINATE_ACK => {
                // Peer is in a state that requires re-negotiation / re-connection
                // but it hasn't informed us properly.
                // This code should never run if the termination was requested by us.

                self.inner.lock().unwrap().error = format!("{:?}", Error::UnexpectedTermAck);
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
                let username = b"alice";
                let password = b"1234";

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
                Ok(())
            }
            chap::FAILURE => {
                println!("authentication failed");
                Ok(())
            }
            _ => Err(Error::InvalidChapCode(chap_code)),
        }
    }

    fn recv_loop(&self) -> Result<()> {
        loop {
            let mut buf = [0; 1024];

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
                        self.handle_ppp(header)
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

                        self.new_discovery_packet(&mut request)?;
                        self.send(&request)?;

                        self.set_state(State::Requesting);

                        println!("sent PADR");
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
                        self.configure()?;

                        Ok(())
                    } else {
                        Err(Error::UnexpectedPads)
                    }
                }
                PADT => {
                    self.set_state(State::Terminated);

                    self.inner.lock().unwrap().socket.close();

                    println!("session terminated by peer (PADT), MAC {}", remote_mac_str);
                    return Ok(());
                }
                _ => Err(Error::InvalidCode(code)),
            } {
                Ok(_) => {}
                Err(e) => println!("error processing packet from MAC {}: {}", remote_mac_str, e),
            }

            if self.state() == State::Terminated {
                self.inner.lock().unwrap().socket.close();

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
    socket: Socket,
    started: bool,
    host_uniq: [u8; 16],
    state: State,
    peer: [u8; 6],
    magic_number: u32,
    error: String,
}
