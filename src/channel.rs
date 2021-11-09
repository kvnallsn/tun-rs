//! A channel-based device that can be used for testing

use crate::{Tun, TunConfig, TunError};
use crossbeam_channel::{Receiver, Sender};
use std::{
    cmp,
    io::{self, Read, Write},
    net::IpAddr,
};

#[derive(Debug)]
pub struct ChannelTun {
    // IP address assigned to this channel
    ip: Option<IpAddr>,

    // user-friendly name of channel / tun
    name: String,

    tx: Sender<Vec<u8>>,

    rx: Receiver<Vec<u8>>,

    rx_buffer: Vec<u8>,
}

impl Read for ChannelTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // check if buffered data exists
        if !self.rx_buffer.is_empty() {
            let amt = cmp::min(self.rx_buffer.len(), buf.len());
            let iter = self.rx_buffer.drain(..amt);
            let data = iter.as_slice();
            buf[..amt].copy_from_slice(&data[..amt]);
            return Ok(amt);
        }

        let mut data = self.rx.recv().unwrap();
        let len = {
            let to_copy = cmp::min(data.len(), buf.len());
            let iter = data.drain(..to_copy);
            let items = iter.as_slice();
            buf[..to_copy].copy_from_slice(items);
            to_copy
        };

        if !data.is_empty() {
            // buffer any remaining items
            self.rx_buffer.append(&mut data);
        }

        Ok(len)
    }
}

impl Write for ChannelTun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        self.tx.send(buf.to_vec()).unwrap();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        // nothing to flush
        Ok(())
    }
}

impl Tun for ChannelTun {
    type Reader = ();
    type Writer = ();
    type PktInfo = ();

    fn up(&self) -> Result<(), TunError> {
        // nothing to do
        Ok(())
    }

    fn down(&self) -> Result<(), TunError> {
        // nothing to do
        Ok(())
    }

    fn split(&self) -> (Self::Reader, Self::Writer) {
        ((), ())
    }

    fn read_packet(&self, _buf: &mut [u8]) -> Result<Self::PktInfo, TunError> {
        // TODO implement this
        Ok(())
    }

    fn write_packet(&self, _buf: &[u8], _af: u32) -> Result<usize, io::Error> {
        // TODO implement this
        Ok(0)
    }
}

impl ChannelTun {
    /// Creates a new ChannelTun pair
    pub fn create(name: &str, _cfg: TunConfig) -> Result<(Self, Self), TunError> {
        let (tx0, rx0) = crossbeam_channel::unbounded();
        let (tx1, rx1) = crossbeam_channel::unbounded();

        let chan_a = Self {
            ip: None,
            name: name.to_owned(),
            rx_buffer: Vec::new(),
            tx: tx0,
            rx: rx1,
        };

        let chan_b = Self {
            ip: None,
            name: name.to_owned(),
            rx_buffer: Vec::new(),
            tx: tx1,
            rx: rx0,
        };

        Ok((chan_a, chan_b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_buffer_size() {
        let (mut local, mut peer) = ChannelTun::create("dummy0", TunConfig::default())
            .expect("failed to create channel tun device");

        let tx_msg = "Hello, there";
        let n = local
            .write(tx_msg.as_bytes())
            .expect("failed to write message via local channel tun");
        assert_eq!(n, tx_msg.len());

        let mut rx_msg = [0u8; 12];
        let n = peer
            .read(&mut rx_msg)
            .expect("failed to read message via peer channel tun");

        assert_eq!(n, tx_msg.len());
        assert_eq!(rx_msg, tx_msg.as_bytes());

        let tx_msg = "General Kenobi";
        let n = peer
            .write(tx_msg.as_bytes())
            .expect("failed to write message via peer channel tun");

        assert_eq!(n, tx_msg.len());

        let mut rx_msg = [0u8; 14];
        let n = local
            .read(&mut rx_msg)
            .expect("failed to read message via local channel tun");

        assert_eq!(n, tx_msg.len());
        assert_eq!(rx_msg, tx_msg.as_bytes());
    }

    #[test]
    fn small_recv_buffer_size() {
        let (mut local, mut peer) = ChannelTun::create("dummy0", TunConfig::default())
            .expect("failed to create channel tun device");

        let tx_msg = "Hello, there";
        local
            .write(tx_msg.as_bytes())
            .expect("failed to write message via local channel tun");

        let mut rx_msg = [0u8; 10];
        let n = peer
            .read(&mut rx_msg)
            .expect("failed to read message via peer channel tun");

        assert_eq!(10, n);
        assert_eq!(rx_msg, tx_msg.as_bytes()[..n]);

        let n = peer
            .read(&mut rx_msg)
            .expect("failed to read message via peer channel tun");

        assert_eq!(2, n);
        assert_eq!(rx_msg[..n], tx_msg.as_bytes()[10..]);
    }

    #[test]
    fn large_recv_buffer_size() {
        let (mut local, mut peer) = ChannelTun::create("dummy0", TunConfig::default())
            .expect("failed to create channel tun device");

        let tx_msg = "Hello, there";
        local
            .write(tx_msg.as_bytes())
            .expect("failed to write message via local channel tun");

        let mut rx_msg = [0u8; 100];
        let n = peer
            .read(&mut rx_msg)
            .expect("failed to read message via peer channel tun");

        assert_eq!(12, n);
        assert_eq!(rx_msg[..n], tx_msg.as_bytes()[..]);
    }
}
