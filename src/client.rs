use crate::error::{Error, Result};

use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::thread;

use pppoe::eth;
use pppoe::header::{PADO, PADS, PADT, PPP};
use pppoe::lcp::{self, ConfigOption, ConfigOptionIterator, CONFIGURE_REQUEST};
use pppoe::packet::{PPPOE_DISCOVERY, PPPOE_SESSION};
use pppoe::ppp::{self, Protocol, LCP};
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
        let host_uniq = rand::random();

        Ok(Self {
            inner: Arc::new(Mutex::new(ClientRef {
                socket: Socket::on_interface(interface)?,
                started: false,
                host_uniq,
                state: State::default(),
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

    fn new_discovery_packet(&self, dst_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.lock().unwrap().socket.mac_address();

        let mut ethernet_header = eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(dst_mac);
        ethernet_header.set_ether_type(PPPOE_DISCOVERY);

        Ok(())
    }

    fn new_session_packet(&self, dst_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.lock().unwrap().socket.mac_address();

        let mut ethernet_header = eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(dst_mac);
        ethernet_header.set_ether_type(PPPOE_SESSION);

        Ok(())
    }

    fn new_ppp_packet(&self, dst_mac: [u8; 6], protocol: Protocol, buf: &mut [u8]) -> Result<()> {
        ppp::HeaderBuilder::create_packet(&mut buf[20..], protocol)?;

        let session_id = self.session_id()?;
        HeaderBuilder::create_ppp(&mut buf[14..], session_id)?;

        self.new_session_packet(dst_mac, buf)?;

        Ok(())
    }

    fn new_lcp_packet(&self, dst_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
        self.new_ppp_packet(dst_mac, Protocol::Lcp, buf)
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
        let n = self.inner.lock().unwrap().socket.recv(buf)?;
        let buf = &buf[..n];

        Ok(Packet::with_buffer(buf)?)
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

        self.new_discovery_packet(BROADCAST, &mut discovery)?;
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

        Ok(())
    }

    fn handle_ppp(&self, src_mac: [u8; 6], header: &Header) -> Result<()> {
        let ppp = ppp::Header::with_buffer(header.payload())?;
        let protocol = ppp.protocol();

        match protocol {
            LCP => self.handle_lcp(src_mac, ppp),
            _ => Err(Error::InvalidProtocol(protocol)),
        }
    }

    fn handle_lcp(&self, src_mac: [u8; 6], header: ppp::Header) -> Result<()> {
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

                self.new_lcp_packet(src_mac, ack)?;
                self.send(ack)?;

                println!("ackknowledged configuration");
                Ok(())
            }
            _ => Err(Error::InvalidLcpCode(lcp_code)),
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
                        self.handle_ppp(remote_mac, header)
                    } else {
                        Err(Error::UnexpectedPpp(remote_mac_str.clone()))
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

                        let mut request = [0; 14 + 6 + 4 + 24];
                        let mut request_header = HeaderBuilder::create_padr(&mut request[14..])?;

                        request_header.add_tag(Tag::ServiceName(b""))?;

                        if let Some(ac_cookie) = ac_cookie {
                            request_header.add_tag(Tag::AcCookie(ac_cookie))?;
                        }

                        self.new_discovery_packet(remote_mac, &mut request)?;
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

                        self.configure()?;

                        Ok(())
                    } else {
                        Err(Error::UnexpectedPads(remote_mac_str.clone()))
                    }
                }
                PADT => {
                    self.set_state(State::Terminated);

                    self.inner.lock().unwrap().socket.close();

                    println!("session terminated by peer, MAC {}", remote_mac_str);
                    return Err(Error::Terminated);
                }
                _ => Err(Error::InvalidCode(code)),
            } {
                Ok(_) => {}
                Err(e) => println!("error processing packet from MAC {}: {}", remote_mac_str, e),
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
}
