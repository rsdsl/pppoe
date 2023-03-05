use rsdsl_pppoe::error::{Error, Result};

use std::env;

use pppoe::header::HeaderBuilder;
use pppoe::packet::PPPOE_DISCOVERY;
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

    Ok(())
}

fn new_broadcast_packet(local_mac: [u8; 6], buf: &mut [u8]) -> Result<()> {
    let mut ethernet_header = pppoe::eth::HeaderBuilder::with_buffer(&mut buf[..14])?;

    ethernet_header.set_src_address(local_mac);
    ethernet_header.set_dst_address(MAC_BROADCAST);
    ethernet_header.set_ether_type(PPPOE_DISCOVERY);

    Ok(())
}
