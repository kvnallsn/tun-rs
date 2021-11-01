use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    udp::{MutableUdpPacket, UdpPacket},
    MutablePacket, Packet,
};
use std::{
    io::{Read, Write},
    thread,
};
use tun_rs::{OsTun, Tun, TunConfig};

fn init_tracing() {
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .init();
}

fn handle_packet(ip: &Ipv4Packet, udp: &UdpPacket) -> MutableIpv4Packet<'static> {
    let mut new_packet =
        MutableIpv4Packet::owned(vec![0; ip.packet().len()]).expect("failed to create packet");
    new_packet.clone_from(ip);

    new_packet.set_identification(0);
    new_packet.set_source(ip.get_destination());
    new_packet.set_destination(ip.get_source());

    let mut udp_vec: Vec<u8> = vec![0; udp.packet().len()];
    let mut new_udp = MutableUdpPacket::new(&mut udp_vec[..]).expect("failed to create udp packet");
    new_udp.clone_from(udp);

    new_udp.set_source(udp.get_destination());
    new_udp.set_destination(udp.get_source());

    new_packet.set_payload(new_udp.packet());

    let checksum = ipv4::checksum(&new_packet.to_immutable());
    new_packet.set_checksum(checksum);
    new_packet
}

fn main() {
    init_tracing();

    let (tx, rx) = crossbeam_channel::bounded(0);
    ctrlc::set_handler(move || tx.send(()).expect("failed to send ctrlc message"))
        .expect("failed to set ctrlc handler");

    let mut tun = OsTun::create(TunConfig::default().ip([192, 168, 70, 100], 24))
        .expect("failed to build tun device");

    tun.up().expect("failed to set tun as up");

    thread::spawn(move || loop {
        let mut buf = [0u8; 1500];
        tun.read(&mut buf).expect("failed to read from device");
        let ip_version = buf[0] >> 4;
        let size = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        match ip_version {
            4 => {
                if let Some(ip) = Ipv4Packet::new(&buf[..size]) {
                    match ip.get_next_level_protocol() {
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ip.payload()) {
                                let pkt = handle_packet(&ip, &udp);
                                tun.write_all(pkt.packet()).expect("failed to write packet");
                            }
                        }
                        _ => { /* ignore other protocols */ }
                    }
                }
            }
            _ => { /* ignore non-ipv4 packets */ }
        }
    });

    println!("waiting for ctrl-c event...");
    rx.recv().expect("failed to wait for ctrl-c event");
    println!("caught ctrl-c, qutting");
}
