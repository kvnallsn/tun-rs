//! Platform-agnostic TUN library

use std::{
    io::{self, Read, Write},
    net::IpAddr,
    sync::Arc,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{OsConfig, OsTun, OsTunConfig};

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

pub trait Tun: Read + Write + Sized {
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
    /// # Errors
    /// * I/O
    fn read_packet(&self, buf: &mut [u8]) -> Result<Self::PktInfo, TunError>;

    /// Writes a packet to the TUN device
    ///
    /// # Arguments
    /// * `buf` - Buffer to write
    /// * `af` - Address Family of packet
    fn write_packet(&self, buf: &[u8], af: u32) -> Result<usize, io::Error>;
}

/// Configuration for a new TUN device
#[derive(Default)]
pub struct TunConfig {
    /// IP address and subnet mask to assign TUN device
    pub(crate) ip: Option<(IpAddr, u8)>,

    /// OS-specific configuration parameters
    pub(crate) os: OsTunConfig,
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
}
