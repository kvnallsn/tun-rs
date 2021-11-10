use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    udp::{MutableUdpPacket, UdpPacket},
    MutablePacket, Packet,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
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

    let stop = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let stop = stop.clone();
        move || stop.store(true, Ordering::Relaxed)
    })
    .expect("failed to set ctrl-c handler");

    let cfg = TunConfig::default()
        .ip([192, 168, 80, 100], 24)
        .packet_info(true);

    #[cfg(target_os = "linux")]
    let cfg = cfg.name("echo0");

    let tun = OsTun::create(cfg).expect("failed to build tun device");

    tun.up().expect("failed to set tun as up");

    println!("waiting for ctrl-c event...");

    while !stop.load(Ordering::Relaxed) {
        let mut buf = [0u8; 1500];
        let (_, pi) = tun
            .read_packet(&mut buf)
            .expect("failed to read from device");

        tracing::info!(?pi, "got packet");

        let ip_version = buf[0] >> 4;
        let size = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        match ip_version {
            4 => {
                if let Some(ip) = Ipv4Packet::new(&buf[..size]) {
                    match ip.get_next_level_protocol() {
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ip.payload()) {
                                let pkt = handle_packet(&ip, &udp);
                                tun.write_packet(pkt.packet(), pi)
                                    .expect("failed to write packet");
                            }
                        }
                        _ => { /* ignore other protocols */ }
                    }
                }
            }
            _ => { /* ignore non-ipv4 packets */ }
        }
    }

    println!("caught ctrl-c, qutting");
}
