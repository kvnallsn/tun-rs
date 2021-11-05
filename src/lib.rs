//! Platform-agnostic TUN library

use std::{
    io::{self, Read, Write},
    net::IpAddr,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{OsTun, OsTunConfig};

#[cfg(feature = "channel")]
mod channel;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("device name has nul bytes at position {pos}")]
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

    #[error("{0}")]
    IO(#[from] io::Error),

    #[error("tunnel error: {0}")]
    Generic(Box<dyn std::error::Error>),
}

pub trait Tun: Read + Write + Sized {
    fn up(&self) -> Result<(), TunError>;

    fn down(&self) -> Result<(), TunError>;
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
