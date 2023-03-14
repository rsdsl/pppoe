use rsdsl_pppoe::client::Client;
use rsdsl_pppoe::error::{Error, Result};

use std::env;
use std::sync::Arc;
use std::thread;

use byteorder::{ByteOrder, NetworkEndian as NE};
use pppoe::packet::IPV4;
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
                "dropping outbound non-IPv4 packet, EtherType: {:04x}",
                ether_type
            );
            continue;
        }

        clt.send_ipv4(&buf[4..])?;
    }
}

fn ppp2tun(clt: Client, tun: Arc<Iface>) -> Result<()> {
    let mut packet_info = [0; 4];
    NE::write_u16(&mut packet_info[2..4], IPV4);

    loop {
        let mut buf = clt.recv_ipv4()?;
        buf = prepend(buf, &packet_info);

        let n = tun.send(&buf)?;
        if n != buf.len() {
            return Err(Error::PartialRequest);
        }
    }
}

fn main() -> Result<()> {
    let link = env::args().nth(1).ok_or(Error::MissingInterface)?;

    let tun = Arc::new(Iface::without_packet_info("rsppp0", Mode::Tun)?);

    let clt = Client::new(&link)?;

    let tun2 = tun.clone();
    let clt2 = clt.clone();
    thread::spawn(move || match tun2ppp(clt2, tun2) {
        Ok(_) => unreachable!(),
        Err(e) => panic!("tun2ppp error: {}", e),
    });

    let tun3 = tun;
    let clt3 = clt.clone();
    thread::spawn(move || match ppp2tun(clt3, tun3) {
        Ok(_) => unreachable!(),
        Err(e) => panic!("ppp2tun error: {}", e),
    });

    clt.run()?;
    Ok(())
}
