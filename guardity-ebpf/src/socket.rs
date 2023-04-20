use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel, programs::LsmContext, BpfContext};
use guardity_common::{AlertSocketConnectV4, AlertSocketConnectV6, SocketBindAlert};

use crate::{
    binprm::current_binprm_inode,
    maps::{
        ALERT_SOCKET_BIND, ALERT_SOCKET_CONNECT_V4, ALERT_SOCKET_CONNECT_V6, ALLOWED_SOCKET_BIND,
        ALLOWED_SOCKET_CONNECT_V4, ALLOWED_SOCKET_CONNECT_V6, DENIED_SOCKET_BIND,
        DENIED_SOCKET_CONNECT_V4, DENIED_SOCKET_CONNECT_V6,
    },
    vmlinux::{sockaddr, sockaddr_in, sockaddr_in6},
    INODE_WILDCARD,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub(crate) fn try_socket_bind(ctx: LsmContext) -> Result<i32, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };

    if unsafe { (*sockaddr).sa_family } != AF_INET {
        return Ok(0);
    }

    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let port = u16::from_be(unsafe { (*sockaddr_in).sin_port });

    let binprm_inode = current_binprm_inode();

    if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&INODE_WILDCARD) } {
        if ports.all {
            if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&INODE_WILDCARD) } {
                if ports.all {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(-1);
                }
                if ports.ports.contains(&port) {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(-1);
                }
            }

            if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&binprm_inode) } {
                if ports.all {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(-1);
                }
                if ports.ports.contains(&port) {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(-1);
                }
            }
        } else {
            if ports.ports.contains(&port) {
                return Ok(0);
            }
        }
    }

    if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&INODE_WILDCARD) } {
        if ports.all {
            if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&INODE_WILDCARD) } {
                if ports.all {
                    return Ok(0);
                }
                if ports.ports.contains(&port) {
                    return Ok(0);
                }
            }

            if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&binprm_inode) } {
                if ports.all {
                    return Ok(0);
                }
                if ports.ports.contains(&port) {
                    return Ok(0);
                }
            }

            ALERT_SOCKET_BIND.output(
                &ctx,
                &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                0,
            );
            return Ok(-1);
        } else {
            if ports.ports.contains(&port) {
                ALERT_SOCKET_BIND.output(
                    &ctx,
                    &SocketBindAlert::new(ctx.pid(), binprm_inode, port),
                    0,
                );
                return Ok(-1);
            }
        }
    }

    Ok(0)
}

#[inline(always)]
fn try_socket_connect_v4(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<i32, c_long> {
    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let addr = u32::from_be(unsafe { (*sockaddr_in).sin_addr.s_addr });

    let binprm_inode = current_binprm_inode();

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
                if addrs.all {
                    ALERT_SOCKET_CONNECT_V4.output(
                        &ctx,
                        &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs.contains(&addr) {
                    ALERT_SOCKET_CONNECT_V4.output(
                        &ctx,
                        &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }

            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&binprm_inode) } {
                if addrs.all {
                    ALERT_SOCKET_CONNECT_V4.output(
                        &ctx,
                        &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs.contains(&addr) {
                    ALERT_SOCKET_CONNECT_V4.output(
                        &ctx,
                        &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }
        } else {
            if addrs.addrs.contains(&addr) {
                return Ok(0);
            }
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
                if addrs.all {
                    return Ok(0);
                }
                if addrs.addrs.contains(&addr) {
                    return Ok(0);
                }
            }

            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&binprm_inode) } {
                if addrs.all {
                    return Ok(0);
                }
                if addrs.addrs.contains(&addr) {
                    return Ok(0);
                }
            }

            ALERT_SOCKET_CONNECT_V4.output(
                &ctx,
                &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                0,
            );
            return Ok(-1);
        } else {
            if addrs.addrs.contains(&addr) {
                ALERT_SOCKET_CONNECT_V4.output(
                    &ctx,
                    &AlertSocketConnectV4::new(ctx.pid(), binprm_inode, addr),
                    0,
                );
                return Ok(-1);
            }
        }
    }

    Ok(0)
}

#[inline(always)]
fn try_socket_connect_v6(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<i32, c_long> {
    let sockaddr_in6: *const sockaddr_in6 = sockaddr as *const sockaddr_in6;

    let sockaddr_in6: sockaddr_in6 = unsafe { bpf_probe_read_kernel(sockaddr_in6)? };
    let addr = unsafe { sockaddr_in6.sin6_addr.in6_u.u6_addr8 };

    let binprm_inode = current_binprm_inode();

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
                if addrs.all {
                    ALERT_SOCKET_CONNECT_V6.output(
                        &ctx,
                        &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs.contains(&addr) {
                    ALERT_SOCKET_CONNECT_V6.output(
                        &ctx,
                        &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }

            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&binprm_inode) } {
                if addrs.all {
                    ALERT_SOCKET_CONNECT_V6.output(
                        &ctx,
                        &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs.contains(&addr) {
                    ALERT_SOCKET_CONNECT_V6.output(
                        &ctx,
                        &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }
        } else {
            if addrs.addrs.contains(&addr) {
                return Ok(0);
            }
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
                if addrs.all {
                    return Ok(0);
                }
                if addrs.addrs.contains(&addr) {
                    return Ok(0);
                }
            }

            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&binprm_inode) } {
                if addrs.all {
                    return Ok(0);
                }
                if addrs.addrs.contains(&addr) {
                    return Ok(0);
                }
            }

            ALERT_SOCKET_CONNECT_V6.output(
                &ctx,
                &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                0,
            );
            return Ok(-1);
        } else {
            if addrs.addrs.contains(&addr) {
                ALERT_SOCKET_CONNECT_V6.output(
                    &ctx,
                    &AlertSocketConnectV6::new(ctx.pid(), binprm_inode, addr),
                    0,
                );
                return Ok(-1);
            }
        }
    }

    Ok(0)
}

pub(crate) fn try_socket_connect(ctx: LsmContext) -> Result<i32, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };
    let sa_family = unsafe { (*sockaddr).sa_family };

    if sa_family == AF_INET {
        return try_socket_connect_v4(ctx, sockaddr);
    } else if sa_family == AF_INET6 {
        return try_socket_connect_v6(ctx, sockaddr);
    }

    Ok(0)
}
