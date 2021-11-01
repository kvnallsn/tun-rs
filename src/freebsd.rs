//! FreeBSD Implementation

use crate::{Tun, TunConfig, TunError};
use std::{
    ffi::CStr,
    io::{self, Read, Write},
    mem::{self, MaybeUninit},
    net::IpAddr,
    os::unix::io::RawFd,
    ptr,
};

const TUN_DEVICE_PATH: &[u8; 9] = b"/dev/tun\0";

// IOCTLs (see sys/sockio.h)
const SIOCAIFADDR: u64 = 0x8044_692b;

/// A generic layer-3 tunnel using the OS's networking primitives
#[derive(Debug)]
pub struct OsTun {
    // opened file descriptor used to read/write to this device
    fd: RawFd,

    // null-terminated device name string
    name: [u8; libc::IFNAMSIZ],
}

impl Read for OsTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n: isize = unsafe { libc::read(self.fd, buf.as_mut_ptr() as _, buf.len()) };
        tracing::trace!("tun read: read {} bytes", n);
        match n {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl Write for OsTun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        tracing::trace!("tun write: writing {} bytes", buf.len());
        match unsafe { libc::write(self.fd, buf.as_ptr() as _, buf.len() as _) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // nothing to flush
        Ok(())
    }
}

impl OsTun {
    /// Creates a new TUN device on the OS
    ///
    /// # Privileges
    /// Requires root (or superuser) privileges to allocate a TUN device
    ///
    /// # Arguments
    /// * `cfg` - tun configuration options
    pub fn create(cfg: TunConfig) -> Result<Self, TunError> {
        // create a new tun device by opening the special device `/dev/tun`
        let tun_dev_path = CStr::from_bytes_with_nul(TUN_DEVICE_PATH.as_ref())
            .map_err(|_| TunError::InvalidCString)?;

        // SAFETY: tun_dev_path is validated above as a CStr, ensuring it
        // has exactly one null byte at the end of the string
        let fd = unsafe { libc::open(tun_dev_path.as_ptr(), libc::O_RDONLY) };
        if fd == -1 {
            return Err(TunError::IO(io::Error::last_os_error()));
        }

        // get the device name
        // fdevname() seems to be missing from the libc crate so we'll go the
        // fstat route with devname_r()

        let mut statbuf = MaybeUninit::<libc::stat>::zeroed();

        // SAFTEY: fd is guarenteed to be valid & statbuf is zerod
        if unsafe { libc::fstat(fd, statbuf.as_mut_ptr()) } == -1 {
            return Err(TunError::IO(io::Error::last_os_error()));
        }

        // SAFETY: fstat() error code has been checked and is guarenteed
        // to be success at this point, assume buffer is initialized
        let statbuf = unsafe { statbuf.assume_init() };

        let mut name = [0u8; libc::IFNAMSIZ];

        // SAFETY: buffer is guarenteed to be large enough to hold the name
        // of the returned interface (IFNAMSIZ)
        if unsafe {
            libc::devname_r(
                statbuf.st_rdev,
                libc::S_IFCHR,
                name.as_mut_ptr() as *mut i8,
                name.len() as i32,
            )
        } == ptr::null_mut()
        {
            return Err(TunError::IO(io::Error::last_os_error()));
        }

        /*
        // consume chars until the first null byte then make it a cstring
        let name: Vec<u8> = name.into_iter().take_while(|&ch| ch != 0).collect();
        let name = CString::new(name).map_err(|e| TunError::DeviceNameContainsNuls {
            pos: e.nul_position(),
        })?;
        */

        let mut tun = Self { fd, name };
        tun.configure(cfg)?;
        Ok(tun)
    }

    /// Applies the tunnel config settings to this TUN device
    ///
    /// # Arguments
    /// * `cfg` - Tunnel Configuration Options
    pub fn configure(&mut self, cfg: TunConfig) -> Result<(), TunError> {
        #[repr(C)]
        #[derive(Debug)]
        struct IfAliasReq {
            ifra_name: [u8; libc::IFNAMSIZ],
            ifra_addr: libc::sockaddr_in,
            ifra_broadaddr: libc::sockaddr_in,
            ifra_mask: libc::sockaddr_in,
            ifra_vhid: i32, // ?? CARP related?
        }

        // SAFETY: socket call uses standard parameters and return value is checked
        let sfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sfd == -1 {
            return Err(TunError::DeviceNotFound);
        }

        if let Some((ip, mask)) = cfg.ip {
            // ioctl SIOCAIFADDR
            match ip {
                IpAddr::V4(ip) => {
                    let ip: u32 = ip.into();

                    let mask: u32 = match mask {
                        32 => u32::MAX,
                        x if x < 32 => u32::MAX - (2_u32.pow((32 - x).into())) + 1,
                        x => return Err(TunError::Ipv4InvalidCidr { cidr: x }),
                    };

                    let broadcast = !mask | ip;

                    let req = IfAliasReq {
                        ifra_name: self.name.clone(),
                        ifra_addr: libc::sockaddr_in {
                            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                            sin_family: libc::AF_INET as u8,
                            sin_port: 0,
                            sin_addr: libc::in_addr { s_addr: ip.to_be() },
                            sin_zero: [0; 8],
                        },
                        ifra_broadaddr: libc::sockaddr_in {
                            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                            sin_family: libc::AF_INET as u8,
                            sin_port: 0,
                            sin_addr: libc::in_addr {
                                s_addr: broadcast.to_be(),
                            },
                            sin_zero: [0; 8],
                        },
                        ifra_mask: libc::sockaddr_in {
                            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                            sin_family: libc::AF_INET as u8,
                            sin_port: 0,
                            sin_addr: libc::in_addr {
                                s_addr: mask.to_be(),
                            },
                            sin_zero: [0; 8],
                        },
                        ifra_vhid: 0,
                    };

                    tracing::trace!("ifreqalias: {:?}", req);

                    // SAFETY: ioctl has been verified using truss to be correct
                    let res = unsafe { libc::ioctl(sfd, SIOCAIFADDR, &req as *const IfAliasReq) };
                    if res == -1 {
                        tracing::error!("errno: {}", nix::errno::Errno::last());
                    }
                }

                IpAddr::V6(_) => {
                    unimplemented!()
                }
            }
        }

        // SAFTEY: sfd is guarenteed to be a valid socket descriptor
        unsafe {
            libc::close(sfd);
        }

        Ok(())
    }
}

impl Tun for OsTun {
    fn up(&self) -> Result<(), TunError> {
        Ok(())
    }

    fn down(&self) -> Result<(), TunError> {
        Ok(())
    }
}

impl Drop for OsTun {
    fn drop(&mut self) {
        // SAFETY: self.fd is guarenteed to be a valid file descriptor
        unsafe { libc::close(self.fd) };
    }
}
