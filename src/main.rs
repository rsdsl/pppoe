use rsdsl_pppoe::client::Client;
use rsdsl_pppoe::config::Config;
use rsdsl_pppoe::error::{Error, Result};

use std::fs::File;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use byteorder::{ByteOrder, NetworkEndian as NE};
use etherparse::{Ipv4Header, TcpHeader, TcpOptionElement};
use pppoe::packet::IPV4;
use rsdsl_ip_config::IpConfig;
use rsdsl_netlinkd::link;
use tun_tap::{Iface, Mode};

const IPPROTO_TCP: u8 = 0x06;

fn prepend<T>(v: Vec<T>, s: &[T]) -> Vec<T>
where
    T: Clone,
{
    let mut tmp = s.to_owned();
    tmp.extend(v);
    tmp
}

fn clamp_mss_if_needed(buf: &mut [u8]) -> Result<()> {
    let ipv4_header = Ipv4Header::from_slice(&buf[4..])?.0;

    if ipv4_header.protocol == IPPROTO_TCP {
        let ipv4_header_bytes = ipv4_header.ihl() as usize * 4;

        let mut tcp_header = TcpHeader::from_slice(&buf[4 + ipv4_header_bytes..])?.0;

        if tcp_header.syn {
            let tcp_header_bytes = tcp_header.header_len() as usize;

            let mut opts = Vec::new();
            for opt in tcp_header.options_iterator() {
                match opt {
                    Ok(mut opt) => {
                        if let TcpOptionElement::MaximumSegmentSize(_) = opt {
                            opt = TcpOptionElement::MaximumSegmentSize(1492);
                        }

                        opts.push(opt);
                    }
                    Err(e) => println!("[pppoe] ignore invalid tcp opt: {}", e),
                }
            }

            tcp_header.set_options(&opts)?;
            tcp_header.checksum = tcp_header.calc_checksum_ipv4(
                &ipv4_header,
                &buf[4 + ipv4_header_bytes + tcp_header_bytes..],
            )?;

            let tcp_header_bytes = tcp_header.header_len() as usize;

            let mut hdr = Vec::new();
            tcp_header.write(&mut hdr)?;

            buf[4 + ipv4_header_bytes..4 + ipv4_header_bytes + tcp_header_bytes]
                .copy_from_slice(&hdr);
        }
    }

    Ok(())
}

fn tun2ppp(tx: mpsc::Sender<Option<Vec<u8>>>, tun: Arc<Iface>) -> Result<()> {
    loop {
        let mut buf = [0; 4 + 1492];
        let n = match tun.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                println!("[pppoe] tun2ppp warning: {}", e);
                continue;
            }
        };
        let buf = &mut buf[..n];

        let ether_type = NE::read_u16(&buf[2..4]);
        if ether_type != IPV4 {
            println!(
                "[pppoe] drop outbound non-ipv4 pkt, ethertype: 0x{:04x}",
                ether_type
            );
            continue;
        }

        match clamp_mss_if_needed(buf) {
            Ok(_) => {}
            Err(e) => println!("[pppoe] ignore outbound mss clamping error: {}", e),
        }

        tx.send(Some(buf[4..].to_vec()))?;
    }
}

fn ppp2tun(rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>, tun: Arc<Iface>) -> Result<()> {
    let rx = rx.lock().unwrap();

    let mut packet_info = [0; 4];
    NE::write_u16(&mut packet_info[2..4], IPV4);

    while let Ok(mut buf) = rx.recv() {
        match clamp_mss_if_needed(&mut buf) {
            Ok(_) => {}
            Err(e) => println!("[pppoe] ignore inbound mss clamping error: {}", e),
        }

        buf = prepend(buf, &packet_info);

        let n = match tun.send(&buf) {
            Ok(v) => v,
            Err(e) => {
                println!("[pppoe] ppp2tun warning: {}", e);
                continue;
            }
        };
        if n != buf.len() {
            return Err(Error::PartialTransmission);
        }
    }

    Ok(())
}

fn write_config(rx: mpsc::Receiver<IpConfig>) -> Result<()> {
    while let Ok(ip_config) = rx.recv() {
        let mut file = File::create(rsdsl_ip_config::LOCATION)?;
        serde_json::to_writer_pretty(&mut file, &ip_config)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut file = File::open("/data/pppoe.conf")?;
    let config: Config = serde_json::from_reader(&mut file)?;

    println!("[pppoe] read config, launch on interface {}", config.link);

    println!("[pppoe] wait for up {}", config.link);
    link::wait_up(config.link.clone())?;

    let tun = Arc::new(Iface::new("rsppp0", Mode::Tun)?);

    let (recv_tx, recv_rx) = mpsc::channel();
    let recv_rx = Arc::new(Mutex::new(recv_rx));

    let (send_tx, send_rx) = mpsc::channel();
    let send_rx = Arc::new(Mutex::new(send_rx));

    let send_tx2 = send_tx.clone();
    let tun2 = tun.clone();

    thread::spawn(move || match tun2ppp(send_tx2, tun2) {
        Ok(_) => {}
        Err(e) => panic!("tun2ppp error: {}", e),
    });

    thread::spawn(move || match ppp2tun(recv_rx, tun) {
        Ok(_) => {}
        Err(e) => panic!("ppp2tun error: {}", e),
    });

    let (ipchange_tx, ipchange_rx) = mpsc::channel();
    thread::spawn(move || match write_config(ipchange_rx) {
        Ok(_) => {}
        Err(e) => panic!("write_config error: {}", e),
    });

    loop {
        println!("[pppoe] connect");

        let clt = Client::new(config.clone())?;

        clt.run(recv_tx.clone(), send_rx.clone(), ipchange_tx.clone())?;

        send_tx.send(None)?;
        println!("[pppoe] disconnect");
    }
}
