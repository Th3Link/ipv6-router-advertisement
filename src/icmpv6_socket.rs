use libc::{IPPROTO_ICMPV6, IPPROTO_IPV6, IPV6_PKTINFO, msghdr, sockaddr_in6};
use socket2::{Domain, Protocol, Socket, Type};
use std::os::fd::IntoRawFd;
use std::{
    io, mem,
    net::{Ipv6Addr, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;

use crate::InterfaceIndex;

#[async_trait::async_trait]
pub trait Icmpv6Socket: Send + Sync {
    async fn receive(&self) -> io::Result<(InterfaceIndex, Ipv6Addr, Vec<u8>)>;
    fn send(
        &self,
        ifindex: InterfaceIndex,
        destination: Ipv6Addr,
        payload: &[u8],
    ) -> io::Result<()>;
}

pub struct RealIcmpv6Socket {
    /// Owned file descriptor (just an i32) moved from socket
    fd: AsyncFd<OwnedFd>,
}

#[async_trait::async_trait]
impl Icmpv6Socket for RealIcmpv6Socket {
    async fn receive(&self) -> io::Result<(InterfaceIndex, Ipv6Addr, Vec<u8>)> {
        let _guard = self.fd.readable().await?;

        let mut buf = [0u8; 1500];
        let mut cmsg_buf = [0u8; 256];

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as _;

        let len = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };

        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        let len = len as usize;
        let payload = buf[..len].to_vec();
        let router_ip = Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
        let ifindex = Self::extract_ifindex(&msg)?;

        Ok((ifindex, router_ip, payload))
    }

    fn send(
        &self,
        ifindex: InterfaceIndex,
        destination: Ipv6Addr,
        payload: &[u8],
    ) -> io::Result<()> {
        let dst = SocketAddrV6::new(destination, 0, 0, ifindex);

        let dst_raw = sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: dst.ip().octets(),
            },
            sin6_scope_id: ifindex,
        };

        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                &payload as *const _ as *const libc::c_void,
                payload.len(),
                0,
                &dst_raw as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_in6>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl RealIcmpv6Socket {
    pub fn new() -> io::Result<Self> {
        let socket = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::from(IPPROTO_ICMPV6)),
        )?;

        socket.set_only_v6(true)?;

        unsafe {
            let on: libc::c_int = 1;
            libc::setsockopt(
                socket.as_raw_fd(),
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                &on as *const _ as *const _,
                mem::size_of::<libc::c_int>() as _,
            );

            // SAFETY: ownership of the raw socket file descriptor is transferred
            // from `socket` into `OwnedFd` and must not be used afterwards.
            let fd = socket.into_raw_fd();
            Self::set_hop_limit_255(fd)?;
            let fd = OwnedFd::from_raw_fd(fd);
            let fd = AsyncFd::new(fd)?;

            Ok(Self { fd })
        }
    }

    /// Set IPv6 hop limit to 255 on a socket.
    ///
    /// Routers MUST ignore RS messages that do not have hop limit 255.
    /// This helper should be called once after creating the socket.
    fn set_hop_limit_255(sock_fd: i32) -> io::Result<()> {
        let hop_limit: libc::c_int = 255;

        let ret = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                &hop_limit as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Extracts the interface index from an IPv6 control message.
    ///
    /// This function scans the ancillary data of a `recvmsg` call for
    /// `IPV6_PKTINFO` and returns the associated interface index.
    ///
    /// Returns an error if no valid packet info is found.
    fn extract_ifindex(msg: &msghdr) -> io::Result<u32> {
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == IPPROTO_IPV6 && (*cmsg).cmsg_type == IPV6_PKTINFO {
                    let pkt = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                    return Ok((*pkt).ipi6_ifindex);
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
        Err(io::ErrorKind::InvalidData.into())
    }
}
