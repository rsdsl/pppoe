use rsdsl_pppoe::client::Client;
use rsdsl_pppoe::config::Config;
use rsdsl_pppoe::error::{Error, Result};

use std::fs::File;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use byteorder::{ByteOrder, NetworkEndian as NE};
use pppoe::packet::IPV4;
use rsdsl_ip_config::IpConfig;
use rsdsl_netlinkd::link;
use tun_tap::{Iface, Mode};

fn prepend<T>(v: Vec<T>, s: &[T]) -> Vec<T>
where
    T: Clone,
{
    let mut tmp = s.to_owned();
    tmp.extend(v);
    tmp
}

fn tun2ppp(tx: mpsc::Sender<Option<Vec<u8>>>, tun: Arc<Iface>) -> Result<()> {
    loop {
        let mut buf = [0; 4 + 1492];
        let n = match tun.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                println!("tun2ppp warning: {}", e);
                continue;
            }
        };
        let buf = &buf[..n];

        let ether_type = NE::read_u16(&buf[2..4]);
        if ether_type != IPV4 {
            println!(
                "drop outbound non-ipv4 pkt, ethertype: 0x{:04x}",
                ether_type
            );
            continue;
        }

        tx.send(Some(buf[4..].to_vec()))?;
    }
}

fn ppp2tun(rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>, tun: Arc<Iface>) -> Result<()> {
    let rx = rx.lock().unwrap();

    let mut packet_info = [0; 4];
    NE::write_u16(&mut packet_info[2..4], IPV4);

    while let Ok(mut buf) = rx.recv() {
        buf = prepend(buf, &packet_info);

        let n = match tun.send(&buf) {
            Ok(v) => v,
            Err(e) => {
                println!("ppp2tun warning: {}", e);
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

    println!("read config, launch on interface {}", config.link);

    println!("wait for up {}", config.link);
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
        println!("connect");

        let clt = Client::new(config.clone())?;

        match clt.run(recv_tx.clone(), send_rx.clone(), ipchange_tx.clone()) {
            Ok(_) => {}
            Err(e) => println!("warning: {}", e),
        }

        send_tx.send(None)?;
        println!("disconnect");
    }
}
