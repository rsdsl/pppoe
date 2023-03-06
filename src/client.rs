use crate::error::{Error, Result};

use std::sync::{Arc, Mutex};
use std::thread;

use pppoe::header::PADO;
use pppoe::packet::PPPOE_DISCOVERY;
use pppoe::HeaderBuilder;
use pppoe::Packet;
use pppoe::Socket;
use pppoe::Tag;

const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

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

    fn new_packet(&self, dst_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
        let local_mac = self.inner.lock().unwrap().socket.mac_address();

        let mut ethernet_header = pppoe::eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

        ethernet_header.set_src_address(local_mac);
        ethernet_header.set_dst_address(dst_mac);
        ethernet_header.set_ether_type(PPPOE_DISCOVERY);

        Ok(())
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
        let host_uniq = self.inner.lock().unwrap().host_uniq;

        let mut discovery = [0; 14 + 6 + 4 + 20];
        let mut discovery_header = HeaderBuilder::create_padi(&mut discovery[14..])?;

        discovery_header.add_tag(Tag::ServiceName(b""))?;
        discovery_header.add_tag(Tag::HostUniq(&host_uniq))?;

        self.new_packet(BROADCAST, &mut discovery)?;
        self.send(&discovery)?;

        println!("sent PADI");

        Ok(())
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

                    println!("offer from MAC {}, AC {}", remote_mac_str, ac_name);
                    Ok(())
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
}
