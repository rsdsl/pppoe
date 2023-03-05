use rsdsl_pppoe::error::{Error, Result};

use std::env;

use pppoe::header::{HeaderBuilder, PADO};
use pppoe::packet::{Packet, PPPOE_DISCOVERY};
use pppoe::socket::Socket;
use pppoe::tag::Tag;

const MAC_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

fn main() -> Result<()> {
    let link = env::args().nth(1).ok_or(Error::MissingInterface)?;

    let host_uniq = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let socket = Socket::on_interface(&link)?;
    let local_mac = socket.mac_address();

    let mut discovery = [0; 14 + 6 + 4 + 20];
    let mut discovery_header = HeaderBuilder::create_padi(&mut discovery[14..])?;

    discovery_header.add_tag(Tag::ServiceName(b""))?;
    discovery_header.add_tag(Tag::HostUniq(&host_uniq))?;

    new_broadcast_packet(local_mac, &mut discovery)?;

    println!("sending PADI");

    let n = socket.send(&discovery)?;
    if n != discovery.len() {
        return Err(Error::PartialRequest);
    }

    let mut offer = [0; 1024];
    let n = socket.recv(&mut offer)?;
    let offer = &offer[..n];

    let offer = Packet::with_buffer(offer)?;
    let offer_header = offer.pppoe_header();
    let offer_code = offer_header.code();

    if offer_code != PADO {
        return Err(Error::ExpectedPado(offer_code));
    }

    let remote_mac = offer.ethernet_header().src_address();
    let ac_name = offer_header
        .tags()
        .find_map(|tag| {
            if let Tag::AcName(ac_name) = tag {
                String::from_utf8(ac_name.to_vec()).ok()
            } else {
                None
            }
        })
        .unwrap_or(String::new());

    let remote_mac_str = remote_mac
        .iter()
        .map(|octet| format!("{:02x}", octet))
        .reduce(|acc, octet| acc + ":" + &octet)
        .unwrap();

    println!("offer from {}, ac name: {}", remote_mac_str, ac_name);

    Ok(())
}

fn new_broadcast_packet(local_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
    let mut ethernet_header = pppoe::eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

    ethernet_header.set_src_address(local_mac);
    ethernet_header.set_dst_address(MAC_BROADCAST);
    ethernet_header.set_ether_type(PPPOE_DISCOVERY);

    Ok(())
}
