use crate::{Tun, TunConfig, TunError};
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Arphrd, Ifa, IfaF, IfaFFlags, Iff, IffFlags, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{self, Ifaddrmsg, Rtattr},
    socket::NlSocketHandle,
    types::RtBuffer,
};

use std::{
    ffi::CString,
    io::{self, Read, Write},
    net::IpAddr,
    os::{raw::c_short, unix::io::RawFd},
};

const TUNSETIFF: u64 = 0x4004_54ca;
const CLONE_DEVICE_PATH: &[u8] = b"/dev/net/tun\0";

//const RTNLGRP_LINK: libc::c_uint = 1;
//const RTNLGRP_IPV4_IFADDR: libc::c_uint = 5;
//const RTNLGRP_IPV6_IFADDR: libc::c_uint = 9;

impl From<NlError> for TunError {
    fn from(err: NlError) -> Self {
        Self::Generic(Box::new(err))
    }
}

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: c_short,
    _pad: [u8; 64],
}

/// A generic layer-3 tunnel using the OS's networking primitives
#[derive(Debug)]
pub struct OsTun {
    // opened file descriptor used to read/write to this device
    fd: RawFd,

    // null-terminated device name string
    name: CString,

    // index of inteface
    index: i32,

    // set to true if packet info has been requested
    packet_info: bool,
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

impl Tun for OsTun {
    // (number of bytes read, address family (if packet info))
    type PktInfo = (u16, u16);

    fn up(&self) -> Result<(), TunError> {
        // mark device as up
        let mut socket = self.open_netlink_socket(&[])?;
        let msg = rtnl::Ifinfomsg::new(
            RtAddrFamily::Unspecified,
            Arphrd::Netrom,
            self.index,
            IffFlags::new(&[Iff::Up]),
            IffFlags::new(&[Iff::Up]),
            RtBuffer::new(),
        );

        let hdr = {
            let len = None;
            let nl_type = Rtm::Newlink;
            let flags = NlmFFlags::new(&[NlmF::Request]);
            let seq = None;
            let pid = None;
            let payload = msg;
            Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
        };

        socket.send(hdr)?;

        Ok(())
    }

    fn down(&self) -> Result<(), TunError> {
        // mark device as up
        let mut socket = self.open_netlink_socket(&[])?;
        let msg = rtnl::Ifinfomsg::new(
            RtAddrFamily::Unspecified,
            Arphrd::Netrom,
            self.index,
            IffFlags::new(&[]),
            IffFlags::new(&[]),
            RtBuffer::new(),
        );

        let hdr = {
            let len = None;
            let nl_type = Rtm::Dellink;
            let flags = NlmFFlags::new(&[NlmF::Request]);
            let seq = None;
            let pid = None;
            let payload = msg;
            Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
        };

        socket.send(hdr)?;
        Ok(())
    }

    fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, Self::PktInfo), TunError> {
        use libc::iovec;
        let mut hdr = [0u8; 4];

        let mut iov = [
            iovec {
                iov_base: hdr.as_mut_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as _,
                iov_len: buf.len(),
            },
        ];

        let idx = match self.packet_info {
            true => 0,
            false => 1,
        };

        tracing::debug!(%self.packet_info, "reading packet from tun");
        let res = unsafe { libc::readv(self.fd, &mut iov[idx] as *mut _, (iov.len() - idx) as _) };
        tracing::debug!("tun read {} bytes", res);
        match res {
            -1 => Err(TunError::IO(io::Error::last_os_error())),
            n => match self.packet_info {
                true => {
                    let flags = u16::from_le_bytes([hdr[0], hdr[1]]);
                    let af = u16::from_be_bytes([hdr[2], hdr[3]]);
                    let sz = (n - 4) as usize;
                    Ok((sz, (flags, af)))
                }
                false => Ok((n as usize, (0, 0))),
            },
        }
    }

    fn write_packet(&self, buf: &[u8], pi: Option<Self::PktInfo>) -> Result<usize, io::Error> {
        use libc::iovec;
        let (flags, af) = match pi {
            Some((flags, af)) => (flags.to_le_bytes(), af.to_be_bytes()),
            None => ([0u8; 2], [0u8, 2])
        };

        let mut iov = [
            iovec {
                iov_base: flags.as_ptr() as _,
                iov_len: flags.len(),
            },
            iovec {
                iov_base: af.as_ptr() as _,
                iov_len: af.len(),
            },
            iovec {
                iov_base: buf.as_ptr() as _,
                iov_len: buf.len(),
            },
        ];

        let idx = match self.packet_info {
            true => 0,
            false => 2,
        };

        match unsafe { libc::writev(self.fd, &mut iov[idx] as *mut _, (iov.len() - idx) as _) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl OsTun {
    /// Creates a new TUN device
    ///
    /// If a TUN device named `name` does not already exist, one will be created.
    ///
    /// Creating a new TUN device requires root privileges or `CAP_NET_ADMIN` to be set on
    /// the binary. To avoid requiring root privileges, a TUN device can be created using
    /// the `iproute2` package.
    ///
    /// To create a TUN device via `iproute` named `tun0` owned by user `fred`:
    /// ```
    /// sudo ip tuntap add dev tun0 mode tun user fred
    /// ```
    ///
    /// Any configuration (setting ips, etc.) will require root privileges or `CAP_NET_ADMIN`
    /// set on the binary.
    ///
    ///
    /// # Arguments
    /// * `name` - Name of TUN device
    /// * `cfg` - Tunnel device configuration
    ///
    /// # Errors
    /// * `name` contains interior null bytes (aka not a c string)
    /// * `name` is too long (longer than `libc::IFNAMSIZ`)
    /// * not run as root user or with CAP_NET_ADMIN capability set
    /// * TUN device fails to create for other reasons
    pub fn create(cfg: TunConfig) -> Result<Self, TunError> {
        let mut cfg = cfg;

        // ensure the device name is present (required on linux)
        let name = match cfg.name.take() {
            Some(name) => name,
            None => return Err(TunError::DeviceNameRequired),
        };

        // sanity check length of device name and check for interior nulls
        let name =
            CString::new(name.as_str()).map_err(|error| TunError::DeviceNameContainsNuls {
                pos: error.nul_position(),
            })?;

        let name_bytes = name.as_bytes();
        if name_bytes.len() > (libc::IFNAMSIZ - 1) {
            return Err(TunError::DeviceNameTooLong {
                len: name_bytes.len(),
                max: libc::IFNAMSIZ,
            });
        }

        // open clone device
        let fd: RawFd = match unsafe { libc::open(CLONE_DEVICE_PATH.as_ptr() as _, libc::O_RDWR) } {
            -1 => return Err(TunError::DeviceOpenFailed),
            x if x < -1 => unreachable!("unexcepted return value from open(): {}", x),
            fd => fd,
        };

        let mut flags = libc::IFF_TUN;
        if !cfg.packet_info {
            flags |= libc::IFF_NO_PI;
        }

        // construct request struct
        let mut req = IfReq {
            name: [0u8; libc::IFNAMSIZ],
            flags: flags as c_short,
            _pad: [0u8; 64],
        };

        // memcpy name into request structure
        req.name[..name_bytes.len()].copy_from_slice(name_bytes);

        // create TUN device
        if unsafe { libc::ioctl(fd, TUNSETIFF as _, &req) } < 0 {
            return Err(TunError::DeviceCreateFailed);
        }

        // fetch interface index
        let index = match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => return Err(TunError::DeviceNotFound),
            x if x >= (i32::MAX as u32) => {
                unreachable!("if_nametoindex returned negative value")
            }
            idx => idx as i32,
        };

        let mut tun = Self {
            fd,
            name,
            index,
            packet_info: cfg.packet_info,
        };
        tun.configure(cfg)?;
        Ok(tun)
    }

    /// Applies the tunnel config settings to this TUN device
    ///
    /// # Arguments
    /// * `cfg` - Tunnel Configuration Options
    pub fn configure(&mut self, cfg: TunConfig) -> Result<(), TunError> {
        if let Some((ip, mask)) = cfg.ip {
            self.assign_ip(ip, mask)?;
        }

        Ok(())
    }

    /// Opens a netlink socket and binds the request multicast groups
    ///
    /// # Arguments
    /// * `groups` - List of multicast groups to bind/listen
    ///
    /// # Errors
    /// * I/O if the netlink socket fails to open
    fn open_netlink_socket(&self, groups: &[u32]) -> Result<NlSocketHandle, TunError> {
        // create netlink socket
        let handle = NlSocketHandle::connect(
            NlFamily::Route,
            None,
            groups,
            //&[RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR],
        )?;

        Ok(handle)
    }

    /// Assign an IP address to the tunnel
    ///
    /// # Arguments
    /// * `ip` - IP Address to assign (e.g., `192.168.70.100`)
    /// * `mask` - CIDR / subnet mask (e.g., `24`)
    ///
    /// # Errors
    /// * I/O if the netlink socket fails to open
    /// * If the ip address is invalid
    /// * If the subnet mask is inappropriate for the ip address
    ///     * i.e., >32 for IPv4 or >128 for IPv6
    /// * If the netlink message fails to send properly
    fn assign_ip(&self, ip: IpAddr, mask: u8) -> Result<(), TunError> {
        tracing::debug!("assigning ip {}/{} to tun device", ip, mask);
        let mut socket = self.open_netlink_socket(&[])?;

        // set ip on device
        let msg = Ifaddrmsg {
            ifa_family: match ip {
                IpAddr::V4(_) => RtAddrFamily::Inet,
                IpAddr::V6(_) => RtAddrFamily::Inet6,
            },
            ifa_prefixlen: mask,
            ifa_flags: IfaFFlags::new(&[IfaF::Permanent]),
            ifa_scope: RtScope::Universe.into(),
            ifa_index: self.index,
            rtattrs: {
                let mut attrs = RtBuffer::new();
                attrs.push(match ip {
                    IpAddr::V4(ip) => Rtattr::new(None, Ifa::Address, &ip.octets()[..])?,
                    IpAddr::V6(ip) => Rtattr::new(None, Ifa::Address, &ip.octets()[..])?,
                });
                attrs.push(match ip {
                    IpAddr::V4(ip) => Rtattr::new(None, Ifa::Local, &ip.octets()[..])?,
                    IpAddr::V6(ip) => Rtattr::new(None, Ifa::Local, &ip.octets()[..])?,
                });
                attrs
            },
        };

        let hdr = {
            let len = None;
            let nl_type = Rtm::Newaddr;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Create, NlmF::Excl]);
            let seq = None;
            let pid = None;
            let payload = msg;
            Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
        };

        socket.send(hdr)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(feature = "root-tests"), ignore)]
    fn root_create_tun_device() {
        let _dev = OsTun::create(TunConfig::default().name("linux0"))
            .expect("failed to create linux tun device");
    }

    #[test]
    #[cfg_attr(not(feature = "root-tests"), ignore)]
    fn root_create_tun_device_with_ip() {
        let _dev = OsTun::create(
            TunConfig::default()
                .name("linux1")
                .ip([192, 168, 70, 100], 24),
        )
        .expect("failed to create linux tun device");
    }
}
