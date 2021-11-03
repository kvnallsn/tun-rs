//! Simple TCP Packet Logging Example
//!
//! Reads from the tunnel device and prints any TCP packets received to the terminal

use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::{io::Read, thread};
use tun_rs::{OsTun, Tun, TunConfig};

fn main() {
    // set up a handler to catch ctrl-c (sigint) signals
    let (tx, rx) = crossbeam_channel::bounded(0);
    ctrlc::set_handler(move || tx.send(()).expect("failed to send ctrlc message"))
        .expect("failed to set ctrlc handler");

    // create a tun device and assign it an ip (in this case `192.168.70.100/24`)
    let mut tun = OsTun::create(TunConfig::default().ip([192, 168, 70, 100], 24))
        .expect("failed to build tun device");

    // mark the tun device as `up`
    tun.up().expect("failed to set tun as up");

    // in a new thread, process any data written to the tun device
    thread::spawn(move || loop {
        let mut buf = [0u8; 1500];
        tun.read(&mut buf).expect("failed to read from device");
        match buf[0] >> 4 {
            4 => {
                if let Some(ip) = Ipv4Packet::new(&buf) {
                    match ip.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                println!(
                                    "{sip}:{sport} -> {dip}:{dport}",
                                    sip = ip.get_source(),
                                    sport = tcp.get_source(),
                                    dip = ip.get_destination(),
                                    dport = tcp.get_destination(),
                                );
                                let mut flags = Vec::new();
                                if tcp.get_flags() & TcpFlags::SYN != 0 {
                                    flags.push("SYN");
                                }
                                if tcp.get_flags() & TcpFlags::ACK != 0 {
                                    flags.push("ACK");
                                }
                                if tcp.get_flags() & TcpFlags::FIN != 0 {
                                    flags.push("FIN");
                                }
                                if tcp.get_flags() & TcpFlags::PSH != 0 {
                                    flags.push("PSH");
                                }
                                if tcp.get_flags() & TcpFlags::RST != 0 {
                                    flags.push("RST");
                                }
                                println!("| Flags {:?}", flags);
                                println!("\\ Payload: {:?}\n", tcp.payload());
                            }
                        }
                        _ => (),
                    }
                }
            }
            x => {
                println!("Only IPv4 is supported. Got version: {}", x);
            }
        }
    });

    println!("waiting for ctrl-c event...");
    rx.recv().expect("failed to wait for ctrl-c event");
    println!("caught ctrl-c, qutting");
}
