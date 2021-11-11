//! Platform-agnostic TUN library

use std::{
    io::{self, Read, Write},
    net::IpAddr,
    sync::Arc,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::OsTun;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::OsTun;

//#[cfg(feature = "channel")]
//mod channel;

#[derive(Clone, Debug)]
pub struct TunDevice(Arc<OsTun>);

impl std::ops::Deref for TunDevice {
    type Target = OsTun;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TunDevice {
    pub fn create(cfg: TunConfig) -> Result<Self, TunError> {
        Ok(Self(Arc::new(OsTun::create(cfg)?)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("string must have exactly one null byte at the end. No more, no less")]
    InvalidCString,

    #[error("device name was not provided but is required")]
    DeviceNameRequired,

    #[error("device name has null bytes at position {pos}")]
    DeviceNameContainsNuls { pos: usize },

    #[error("device name too long. got len: {len}, max len: {max}")]
    DeviceNameTooLong { len: usize, max: usize },

    #[error("device name contains non-unicode (utf-8) characters")]
    DeviceNameNotUnicode,

    #[error("failed to open tun device")]
    DeviceOpenFailed,

    #[error("failed to create tun device")]
    DeviceCreateFailed,

    #[error("failed to find device")]
    DeviceNotFound,

    #[error("cidr must be between 0 and 32, got {cidr}")]
    Ipv4InvalidCidr { cidr: u8 },

    #[error("buffer too small")]
    BufferTooSmall,

    #[error("read didn't produce enough data")]
    NotEnoughData,

    #[error("{0}")]
    IO(#[from] io::Error),

    #[error("tunnel error: {0}")]
    Generic(Box<dyn std::error::Error>),
}

pub trait Tun: Sized {
    type PktInfo;

    /// Marks the device as up on the system
    fn up(&self) -> Result<(), TunError>;

    /// Marks the device as down on the system
    fn down(&self) -> Result<(), TunError>;

    /// Reads a packet from this tun device, including potentially packet information
    ///
    /// The buffer must be at least 5 bytes or an error is returned
    ///
    /// # Arguments
    /// * `buf` - buffer to read data into
    ///
    /// # Returns
    /// `(bytes read, packet_info)`
    /// A tuple containing the number of bytes read into `buf` and any
    /// packet information (if enabled)
    ///
    /// # Errors
    /// * I/O
    fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, Self::PktInfo), TunError>;

    /// Writes a packet to the TUN device
    ///
    /// # Arguments
    /// * `buf` - Buffer to write
    /// * `af` - Address Family of packet
    fn write_packet(&self, buf: &[u8], pi: Self::PktInfo) -> Result<usize, io::Error>;

    /// Returns a blank/empty packet info struct
    ///
    /// Useful for methods where you have to call `write_packet` but packet info hasn't been
    /// provided
    fn blank_pktinfo(&self) -> Self::PktInfo;
}

impl<T> Tun for Arc<T>
where
    T: Tun,
{
    type PktInfo = T::PktInfo;

    fn up(&self) -> Result<(), TunError> {
        self.as_ref().up()
    }

    fn down(&self) -> Result<(), TunError> {
        self.as_ref().down()
    }

    fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, Self::PktInfo), TunError> {
        self.as_ref().read_packet(buf)
    }

    fn write_packet(&self, buf: &[u8], pi: Self::PktInfo) -> Result<usize, io::Error> {
        self.as_ref().write_packet(buf, pi)
    }

    fn blank_pktinfo(&self) -> Self::PktInfo {
        self.as_ref().blank_pktinfo()
    }
}

/// Configuration for a new TUN device
#[derive(Debug, Default)]
pub struct TunConfig {
    /// IP address and subnet mask to assign TUN device
    pub(crate) ip: Option<(IpAddr, u8)>,

    /// Name to assign to this TUN interface
    pub(crate) name: Option<String>,

    /// Enables (or disables) additional packet info on read
    pub(crate) packet_info: bool,
}

impl TunConfig {
    /// Sets IP address and CIDR (mask) to assign to TUN device
    ///
    /// Max CIDR values:
    /// * `IPv4`: 32
    /// * `IPv6`: 128
    ///
    /// # Arguments
    /// * `ip` - IPv4 or IPv6 address
    /// * `cidr` - Classless Inter-Domain Routing mask
    pub fn ip(mut self, ip: impl Into<IpAddr>, cidr: u8) -> Self {
        self.ip = Some((ip.into(), cidr));
        self
    }

    /// Sets the name of this interface
    ///
    /// # Supported OSes:
    /// * Linux
    ///
    /// # Arguments
    /// * `name` - Unique name to assign to this interface
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Enables (or disables) additional packet information
    ///
    /// Some operating systems support returning additional information about
    /// the IP packet that was just read in and prepend it before the rest of
    /// the data.
    ///
    /// # Supported OSes:
    /// * Linux
    /// * FreeBSD
    ///
    /// # Arguments
    /// * `enabled` - True to enabled packet info, false to disable
    pub fn packet_info(mut self, enabled: bool) -> Self {
        self.packet_info = enabled;
        self
    }
}
