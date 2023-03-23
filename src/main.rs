use rsdsl_pppoe::client::Client;
use rsdsl_pppoe::config::Config;
use rsdsl_pppoe::error::{Error, Result};

use std::fs::File;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

fn tun2ppp(clt: Client, tun: Arc<Iface>) -> Result<()> {
    loop {
        let mut buf = [0; 1504];
        let n = tun.recv(&mut buf)?;
        let buf = &buf[..n];

        let ether_type = NE::read_u16(&buf[2..4]);
        if ether_type != IPV4 {
            println!(
                "dropping outbound non-IPv4 packet, EtherType: 0x{:04x}",
                ether_type
            );
            continue;
        }

        clt.send_ipv4(&buf[4..])?;
    }
}

fn ppp2tun(rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>, tun: Arc<Iface>) -> Result<()> {
    let rx = rx.lock().unwrap();

    let mut packet_info = [0; 4];
    NE::write_u16(&mut packet_info[2..4], IPV4);

    while let Ok(mut buf) = rx.recv() {
        buf = prepend(buf, &packet_info);

        let n = tun.send(&buf)?;
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

    println!("read config, launching on interface {}", config.link);

    while !link::is_up(config.link.clone())? {
        println!("waiting for {} to come up", config.link);
        thread::sleep(Duration::from_secs(8));
    }

    let (tx, rx) = mpsc::channel();
    let tun = Arc::new(Iface::new("rsppp0", Mode::Tun)?);

    let rx = Arc::new(Mutex::new(rx));

    loop {
        println!("connecting...");

        let clt = Client::new(config.clone())?;

        let rx2 = rx.clone();
        let tun2 = tun.clone();
        let tun3 = tun.clone();
        let clt2 = clt.clone();
        thread::spawn(move || match tun2ppp(clt2, tun2) {
            Ok(_) => {}
            Err(e) => panic!("tun2ppp error: {}", e),
        });

        thread::spawn(move || match ppp2tun(rx2, tun3) {
            Ok(_) => {}
            Err(e) => panic!("ppp2tun error: {}", e),
        });

        let (ipchange_tx, ipchange_rx) = mpsc::channel();
        thread::spawn(move || match write_config(ipchange_rx) {
            Ok(_) => {}
            Err(e) => panic!("write_config error: {}", e),
        });

        clt.run(tx.clone(), ipchange_tx)?;
        println!("connection lost");
    }
}
