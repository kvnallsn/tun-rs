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

// IOCTLs (source file listed after IOCTL number)
const SIOCAIFADDR: u64 = 0x8044_692b; // sys/sockio.h
const SIOCSIFFLAGS: u64 = 0x8020_6910; // sys/sockio.h
const SIOCGIFFLAGS: u64 = 0xc020_6911; // sys/sockio.h
const SIOCIFDESTROY: u64 = 0x8020_6979; // sys/sockio.h
const TUNSIFMODE: u64 = 0x8004_745e; // net/if_tun.h
const TUNSIFHEAD: u64 = 0x8004_7460; // net/if_tun.h

/// A generic layer-3 tunnel using the OS's networking primitives
#[derive(Debug)]
pub struct OsTun {
    // opened file descriptor used to read/write to this device
    fd: RawFd,

    // opened socket descriptor (used in socket ioctls)
    sock_fd: RawFd,

    // null-terminated device name string
    name: [u8; libc::IFNAMSIZ],

    // true if TUNSIFHEAD is set
    //
    // TUNSIFHEAD prepends each packet with the 4-byte (32-bit)
    // address family in network byte order (aka big endian)
    packet_info: bool,
}

/// IOCTL type to set an interface's address
#[repr(C)]
#[derive(Debug)]
struct IfAliasReq {
    /// Name of interface (e.g., `tun0`)
    ifra_name: [u8; libc::IFNAMSIZ],

    /// IPv4 Address to set
    ifra_addr: libc::sockaddr_in,

    /// Broadcast address of CIDR (Broadcast mode)
    /// Destination address (Point-to-Point mode)
    ifra_broadaddr: libc::sockaddr_in,

    /// Subnet mask
    ifra_mask: libc::sockaddr_in,

    /// ?? CARP Related
    ifra_vhid: i32,
}

#[repr(C)]
struct IfFlagsReq {
    /// Name of interface (e.g., `tun0`)
    ifr_name: [u8; libc::IFNAMSIZ],

    /// Flags set on this interface
    ifru_flags: i32,

    /// additional data (union)
    #[allow(dead_code)]
    pad: [u8; 12],
}

impl Read for OsTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is guarenteed to be a valid u8 pointer and we don't exceed it's length
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

        // SAFETY: self.fd is guarenteed to be a valid/opened file descripter
        //         buf is guarenteed to be a valid u8 pointer with a set length
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
        // 1. create a new tun device by opening the special device `/dev/tun`
        let tun_dev_path = CStr::from_bytes_with_nul(TUN_DEVICE_PATH.as_ref())
            .map_err(|_| TunError::InvalidCString)?;

        // SAFETY: tun_dev_path is validated above as a CStr, ensuring it
        // has exactly one null byte at the end of the string
        let fd = unsafe { libc::open(tun_dev_path.as_ptr(), libc::O_RDWR) };
        if fd == -1 {
            return Err(TunError::IO(io::Error::last_os_error()));
        }

        // 2. set the device to broadcast mode (vs. point to point) w/ multicast
        let flags: i32 = libc::IFF_BROADCAST | libc::IFF_MULTICAST;

        // SAFETY: ioctl has been verified using truss to be correct
        if unsafe { libc::ioctl(fd, TUNSIFMODE, &flags as *const i32) } == -1 {
            tracing::error!("failed to set interface to broadcast mode");
            return Err(TunError::Generic(Box::new(nix::errno::Errno::last())));
        }

        // 3. get the device name
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

        // 4. create socket file descriptor used to configure interface
        //(via socket ioctls)
        // SAFETY: socket call uses standard parameters and return value is checked
        let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock_fd == -1 {
            return Err(TunError::DeviceNotFound);
        }

        // 4. create OsTun instance
        let mut tun = Self {
            fd,
            sock_fd,
            name,
            packet_info: cfg.packet_info,
        };

        // 5. configure device
        tun.configure(cfg)?;

        Ok(tun)
    }

    /// Applies the tunnel config settings to this TUN device
    ///
    /// # Arguments
    /// * `cfg` - Tunnel Configuration Options
    ///
    /// # Errors
    /// * UDP config socket fails to open
    /// * An invalid CIDR is passed with the IP
    /// * Fails to set the IP address
    pub fn configure(&mut self, cfg: TunConfig) -> Result<(), TunError> {
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
                    let res = unsafe {
                        libc::ioctl(self.sock_fd, SIOCAIFADDR, &req as *const IfAliasReq)
                    };
                    if res == -1 {
                        tracing::error!("errno: {}", nix::errno::Errno::last());
                    }
                }

                IpAddr::V6(_) => {
                    unimplemented!()
                }
            }
        }

        if cfg.packet_info {
            // SAFETY:
            if unsafe { libc::ioctl(self.fd, TUNSIFHEAD, &1) } == -1 {
                tracing::warn!(
                    "failed to set multi-af mode (packet_info): {}",
                    nix::errno::Errno::last()
                );
            }
        }

        Ok(())
    }

    /// Retrieves the interface's flags
    fn get_ifflags(&self) -> Result<IfFlagsReq, TunError> {
        let mut req = IfFlagsReq {
            ifr_name: self.name.clone(),
            ifru_flags: 0,
            pad: [0; 12],
        };

        // SAFETY: ioctl has been verified using truss to be correct
        if unsafe { libc::ioctl(self.sock_fd, SIOCGIFFLAGS, &mut req as *mut _) } == -1 {
            return Err(TunError::Generic(Box::new(nix::errno::Errno::last())));
        }

        Ok(req)
    }
}

impl Tun for OsTun {
    type PktInfo = (usize, u32);

    fn up(&self) -> Result<(), TunError> {
        let mut req = self.get_ifflags()?;
        tracing::debug!("got flags: {:x}", req.ifru_flags);
        req.ifru_flags |= libc::IFF_UP;
        tracing::debug!("set flags: {:x}", req.ifru_flags);

        // SAFETY: ioctl has been verified using truss to be correct
        if unsafe { libc::ioctl(self.sock_fd, SIOCSIFFLAGS, &req as *const _) } == -1 {
            return Err(TunError::Generic(Box::new(nix::errno::Errno::last())));
        }

        Ok(())
    }

    fn down(&self) -> Result<(), TunError> {
        let mut req = self.get_ifflags()?;
        req.ifru_flags &= !libc::IFF_UP;

        // SAFETY: ioctl has been verified using truss to be correct
        if unsafe { libc::ioctl(self.sock_fd, SIOCSIFFLAGS, &req as *const _) } == -1 {
            return Err(TunError::Generic(Box::new(nix::errno::Errno::last())));
        }

        Ok(())
    }

    /// Reads a packet from this tun device, including potentially packet information
    ///
    /// The buffer must be at least 5 bytes or an error is returned
    ///
    /// # Arguments
    /// * `buf` - buffer to read data into
    ///
    /// # Returns
    /// * A tuple containing the total number of bytes read and (optionally)
    /// the address family if `packet_info` is enabled
    ///
    /// # Errors
    /// * I/O
    fn read_packet(&self, buf: &mut [u8]) -> Result<Self::PktInfo, TunError> {
        use libc::iovec;

        // packet info data is the first four bytes (if enabled)
        let mut hdr = [0u8; 4];

        let iovs = [
            iovec {
                iov_base: hdr.as_mut_ptr() as *mut libc::c_void,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];

        let idx = match self.packet_info {
            true => 0,
            false => 1,
        };

        // SAFETY: hdr and buf are guarenteed to be valid buffers
        let n: isize =
            unsafe { libc::readv(self.fd, &iovs[idx] as *const _, (iovs.len() - idx) as _) };
        tracing::trace!("tun read: read {} bytes", n);

        match n {
            -1 => Err(TunError::IO(io::Error::last_os_error())),
            n => Ok((n as usize, u32::from_be_bytes(hdr))),
        }
    }

    /// Writes a packet to the TUN device
    ///
    /// # Arguments
    /// * `buf` - Buffer to write
    /// * `af` - Address Family of packet
    fn write_packet(&self, buf: &[u8], af: u32) -> Result<usize, io::Error> {
        use libc::iovec;

        let hdr = af.to_be_bytes();
        let iovs = [
            iovec {
                iov_base: hdr.as_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: buf.as_ptr() as _,
                iov_len: buf.len(),
            },
        ];

        let idx = match self.packet_info {
            true => 0,
            false => 1,
        };

        // SAFETY: self.fd is guarenteed to be a valid/opened file descripter
        //         buf is guarenteed to be a valid u8 pointer with a set length
        match unsafe { libc::writev(self.fd, &iovs[idx] as *const _, (iovs.len() - idx) as _) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl Drop for OsTun {
    fn drop(&mut self) {
        tracing::debug!("dropping interface");

        // 1. close interface file descripter
        // SAFETY: self.fd is guarenteed to be a valid file descriptor
        if unsafe { libc::close(self.fd) } == -1 {
            tracing::error!("failed to close device fd");
        }

        // 2. delete the interface
        let req = IfFlagsReq {
            ifr_name: self.name.clone(),
            ifru_flags: 0,
            pad: [0; 12],
        };

        if unsafe { libc::ioctl(self.sock_fd, SIOCIFDESTROY, &req as *const _) } == -1 {
            tracing::error!("failed to delete interface");
        }

        // SAFTEY: sfd is guarenteed to be a valid socket descriptor
        if unsafe { libc::close(self.sock_fd) } == -1 {
            tracing::error!("failed to close sock fd");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(feature = "root-tests"), ignore)]
    fn create_device() -> Result<(), TunError> {
        // 1. Create a device with the ip 192.168.70.100/24
        let cfg = TunConfig::default().ip([192, 168, 70, 100], 24);
        let tun = OsTun::create(cfg)?;

        // set tun up
        tun.up()?;

        // set tun down
        tun.down()?;

        // set tun up
        tun.up()?;

        // drop tun to delete interface
        drop(tun);

        Ok(())
    }
}
