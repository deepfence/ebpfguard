use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel, programs::LsmContext, BpfContext};
use guardity_common::{AlertSocketConnect, MAX_IPV4ADDRS, MAX_IPV6ADDRS};

use crate::{
    binprm::current_binprm_inode,
    consts::{AF_INET, AF_INET6, INODE_WILDCARD},
    maps::{
        ALERT_SOCKET_CONNECT, ALLOWED_SOCKET_CONNECT_V4, ALLOWED_SOCKET_CONNECT_V6,
        DENIED_SOCKET_CONNECT_V4, DENIED_SOCKET_CONNECT_V6,
    },
    vmlinux::{sockaddr, sockaddr_in, sockaddr_in6},
};

/// Inspects the context of `socket_connect` LSM hook and decides whether to
/// allow or deny the operation based on the state of the
/// `ALLOWED_SOCKET_CONNECT_V4`/`ALLOWED_SOCKET_CONNECT_V6` and
/// `DENIED_SOCKET_CONNECT_V4`/`DENIED_SOCKET_CONNECT_V6` maps.
pub fn socket_connect(ctx: LsmContext) -> Result<i32, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };
    let sa_family = unsafe { (*sockaddr).sa_family };

    match sa_family {
        AF_INET => socket_connect_v4(ctx, sockaddr),
        AF_INET6 => socket_connect_v6(ctx, sockaddr),
        _ => Ok(0),
    }
}

#[inline(always)]
fn socket_connect_v4(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<i32, c_long> {
    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let addr = u32::from_be(unsafe { (*sockaddr_in).sin_addr.s_addr });

    let binprm_inode = current_binprm_inode();

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all() {
            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
                if addrs.all() {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }

            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&binprm_inode) } {
                if addrs.all() {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }
        } else {
            if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                return Ok(0);
            }
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all() {
            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
                if addrs.all() {
                    return Ok(0);
                }
                if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                    return Ok(0);
                }
            }

            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&binprm_inode) } {
                if addrs.all() {
                    return Ok(0);
                }
                if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                    return Ok(0);
                }
            }

            ALERT_SOCKET_CONNECT.output(
                &ctx,
                &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                0,
            );
            return Ok(-1);
        } else {
            if addrs.addrs[..MAX_IPV4ADDRS].contains(&addr) {
                ALERT_SOCKET_CONNECT.output(
                    &ctx,
                    &AlertSocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                    0,
                );
                return Ok(-1);
            }
        }
    }

    Ok(0)
}

#[inline(always)]
fn socket_connect_v6(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<i32, c_long> {
    let sockaddr_in6: *const sockaddr_in6 = sockaddr as *const sockaddr_in6;

    let sockaddr_in6: sockaddr_in6 = unsafe { bpf_probe_read_kernel(sockaddr_in6)? };
    let addr = unsafe { sockaddr_in6.sin6_addr.in6_u.u6_addr8 };

    let binprm_inode = current_binprm_inode();

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all() {
            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
                if addrs.all() {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }

            if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&binprm_inode) } {
                if addrs.all() {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
                if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                    ALERT_SOCKET_CONNECT.output(
                        &ctx,
                        &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                        0,
                    );
                    return Ok(-1);
                }
            }
        } else {
            if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                return Ok(0);
            }
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all() {
            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
                if addrs.all() {
                    return Ok(0);
                }
                if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                    return Ok(0);
                }
            }

            if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&binprm_inode) } {
                if addrs.all() {
                    return Ok(0);
                }
                if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                    return Ok(0);
                }
            }

            ALERT_SOCKET_CONNECT.output(
                &ctx,
                &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                0,
            );
            return Ok(-1);
        } else {
            if addrs.addrs[..MAX_IPV6ADDRS].contains(&addr) {
                ALERT_SOCKET_CONNECT.output(
                    &ctx,
                    &AlertSocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                    0,
                );
                return Ok(-1);
            }
        }
    }

    Ok(0)
}