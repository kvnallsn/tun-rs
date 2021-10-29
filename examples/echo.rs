use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket},
    MutablePacket, Packet,
};
use rand::RngCore;
use std::{
    io::{Read, Write},
    thread,
};
use tun_rs::{OsTun, Tun, TunConfig};

macro_rules! isset {
    ($flags:expr, $flag:expr) => {
        $flags & $flag == $flag
    };
}

fn init_tracing() {
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .init();
}

fn handle_syn(ip: &Ipv4Packet, tcp: &TcpPacket) -> MutableIpv4Packet<'static> {
    let mut new_packet =
        MutableIpv4Packet::owned(vec![0; ip.packet().len()]).expect("failed to create packet");
    new_packet.clone_from(ip);

    new_packet.set_identification(0);
    new_packet.set_source(ip.get_destination());
    new_packet.set_destination(ip.get_source());

    let mut tcp_vec: Vec<u8> = vec![0; tcp.packet().len()];
    let mut new_tcp = MutableTcpPacket::new(&mut tcp_vec[..]).expect("failed to create tcp packet");
    new_tcp.clone_from(tcp);

    let mut rand = rand::thread_rng();
    let mut options = Vec::new();
    for option in tcp.get_options_iter() {
        tracing::debug!(
            "option {:?}: {:?} [{:?}]",
            option.get_number(),
            option.get_length_raw(),
            option.packet(),
        );
        let pkt = option.packet();
        match option.get_number() {
            TcpOptionNumbers::NOP => options.push(TcpOption::nop()),
            TcpOptionNumbers::MSS => {
                //let len = option.get_length_raw()[0] as usize;
                let mss = u16::from_be_bytes([pkt[2], pkt[3]]);
                options.push(TcpOption::mss(mss));
            }
            TcpOptionNumbers::WSCALE => {
                options.push(TcpOption::wscale(pkt[2]));
            }
            TcpOptionNumbers::SACK_PERMITTED => {
                options.push(TcpOption::sack_perm());
            }
            TcpOptionNumbers::SACK => (),
            TcpOptionNumbers::TIMESTAMPS => {
                let my = u32::from_be_bytes([pkt[2], pkt[3], pkt[4], pkt[5]]);
                //let their = u32::from_be_bytes([pkt[6], pkt[7], pkt[8], pkt[9]]);
                options.push(TcpOption::timestamp(my, my));
            }
            TcpOptionNumbers::EOL => (),
            _ => (),
        }
    }
    new_tcp.set_source(tcp.get_destination());
    new_tcp.set_destination(tcp.get_source());
    new_tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    new_tcp.set_sequence(rand.next_u32());
    new_tcp.set_acknowledgement(tcp.get_sequence() + 1);
    new_tcp.set_options(&options);

    new_packet.set_payload(new_tcp.packet());

    let checksum = ipv4::checksum(&new_packet.to_immutable());
    new_packet.set_checksum(checksum);

    new_packet
}

fn main() {
    init_tracing();

    let (tx, rx) = crossbeam_channel::bounded(0);
    ctrlc::set_handler(move || tx.send(()).expect("failed to send ctrlc message"))
        .expect("failed to set ctrlc handler");

    let mut tun = OsTun::create("dune0", TunConfig::default().ip([192, 168, 70, 100], 24))
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
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                let flags = tcp.get_flags();
                                if isset!(flags, TcpFlags::SYN) && !isset!(flags, TcpFlags::ACK) {
                                    // send syn-ack response
                                    let packet = handle_syn(&ip, &tcp);
                                    tun.write_all(packet.packet())
                                        .expect("failed to write packet");
                                }

                                if isset!(flags, TcpFlags::SYN) && isset!(flags, TcpFlags::ACK) {
                                    // send ack response
                                }

                                if !isset!(flags, TcpFlags::SYN) {
                                    // echo contents
                                }
                            }
                        }
                        _ => (),
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
