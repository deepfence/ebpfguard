use aya_bpf::{cty::c_long, programs::LsmContext, BpfContext};
use guardity_common::SocketBindAlert;

use crate::{
    binprm::current_binprm_inode,
    maps::{ALERT_SOCKET_BIND, ALLOWED_SOCKET_BIND, DENIED_SOCKET_BIND},
    vmlinux::{sockaddr, sockaddr_in},
    INODE_WILDCARD,
};

const AF_INET: u16 = 2;

pub(crate) fn try_socket_bind(ctx: LsmContext) -> Result<i32, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };

    if unsafe { (*sockaddr).sa_family } != AF_INET {
        return Ok(0);
    }

    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    // let addr = u32::from_be(unsafe { (*sockaddr_in).sin_addr.s_addr });
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

pub(crate) fn try_socket_connect(ctx: LsmContext) -> Result<i32, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };

    if unsafe { (*sockaddr).sa_family } != AF_INET {
        return Ok(0);
    }

    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let addr = u32::from_be(unsafe { (*sockaddr_in).sin_addr.s_addr });
    let port = u16::from_be(unsafe { (*sockaddr_in).sin_port });

    let binprm_inode = current_binprm_inode();

    Ok(0)
}
