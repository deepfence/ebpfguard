use aya_bpf::{
    cty::c_long, helpers::bpf_probe_read_kernel, maps::HashMap, programs::LsmContext, BpfContext,
};
use ebpfguard_common::{
    alerts,
    consts::INODE_WILDCARD,
    policy::{IpAddrs, Ipv4Addrs, Ipv6Addrs},
};

use crate::{
    binprm::current_binprm_inode,
    consts::{AF_INET, AF_INET6},
    maps::{
        ALERT_SOCKET_CONNECT, ALLOWED_SOCKET_CONNECT_V4, ALLOWED_SOCKET_CONNECT_V6,
        DENIED_SOCKET_CONNECT_V4, DENIED_SOCKET_CONNECT_V6,
    },
    vmlinux::{sockaddr, sockaddr_in, sockaddr_in6},
    Action, Mode,
};

/// Inspects the context of `socket_connect` LSM hook and decides whether to
/// allow or deny the operation based on the state of the
/// `ALLOWED_SOCKET_CONNECT_V4`/`ALLOWED_SOCKET_CONNECT_V6` and
/// `DENIED_SOCKET_CONNECT_V4`/`DENIED_SOCKET_CONNECT_V6` maps.
///
/// # Example
///
/// ```rust
/// use aya_bpf::{macros::lsm, programs::LsmContext};
/// use ebpfguard_ebpf::socket_connect;
///
/// #[lsm(name = "my_program")]
/// pub fn my_program(ctx: LsmContext) -> i32 {
///     match socket_connect(ctx) {
///         Ok(ret) => ret.into(),
///         Err(_) => 0,
///     }
/// }
/// ```
pub fn socket_connect(ctx: LsmContext) -> Result<Action, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };
    let sa_family = unsafe { (*sockaddr).sa_family };

    match sa_family {
        AF_INET => socket_connect_v4(ctx, sockaddr),
        AF_INET6 => socket_connect_v6(ctx, sockaddr),
        _ => Ok(Action::Allow),
    }
}

#[inline(always)]
fn socket_connect_v4(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<Action, c_long> {
    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let addr = u32::from_be(unsafe { (*sockaddr_in).sin_addr.s_addr });

    let binprm_inode = current_binprm_inode()?;

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all() {
            return Ok(check_conditions_and_alert_v4(
                &ctx,
                &DENIED_SOCKET_CONNECT_V4,
                addr,
                binprm_inode,
                Mode::Denylist,
            ));
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V4.get(&INODE_WILDCARD) } {
        if addrs.all() {
            return Ok(check_conditions_and_alert_v4(
                &ctx,
                &ALLOWED_SOCKET_CONNECT_V4,
                addr,
                binprm_inode,
                Mode::Allowlist,
            ));
        }
    }

    Ok(Action::Allow)
}

#[inline(always)]
fn socket_connect_v6(ctx: LsmContext, sockaddr: *const sockaddr) -> Result<Action, c_long> {
    let sockaddr_in6: *const sockaddr_in6 = sockaddr as *const sockaddr_in6;

    let sockaddr_in6: sockaddr_in6 = unsafe { bpf_probe_read_kernel(sockaddr_in6)? };
    let addr = unsafe { sockaddr_in6.sin6_addr.in6_u.u6_addr8 };

    let binprm_inode = current_binprm_inode()?;

    if let Some(addrs) = unsafe { ALLOWED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all() {
            return Ok(check_conditions_and_alert_v6(
                &ctx,
                &DENIED_SOCKET_CONNECT_V6,
                addr,
                binprm_inode,
                Mode::Denylist,
            ));
        }
    }

    if let Some(addrs) = unsafe { DENIED_SOCKET_CONNECT_V6.get(&INODE_WILDCARD) } {
        if addrs.all() {
            return Ok(check_conditions_and_alert_v6(
                &ctx,
                &ALLOWED_SOCKET_CONNECT_V6,
                addr,
                binprm_inode,
                Mode::Allowlist,
            ));
        }
    }

    Ok(Action::Allow)
}

#[inline(always)]
fn check_conditions_and_alert_v4(
    ctx: &LsmContext,
    map: &HashMap<u64, Ipv4Addrs>,
    addr: u32,
    binprm_inode: u64,
    mode: Mode,
) -> Action {
    match check_conditions(map, addr, binprm_inode, mode) {
        Action::Deny => {
            ALERT_SOCKET_CONNECT.output(
                ctx,
                &alerts::SocketConnect::new_ipv4(ctx.pid(), binprm_inode, addr),
                0,
            );
            Action::Deny
        }
        action => action,
    }
}

#[inline(always)]
fn check_conditions_and_alert_v6(
    ctx: &LsmContext,
    map: &HashMap<u64, Ipv6Addrs>,
    addr: [u8; 16],
    binprm_inode: u64,
    mode: Mode,
) -> Action {
    match check_conditions(map, addr, binprm_inode, mode) {
        Action::Deny => {
            ALERT_SOCKET_CONNECT.output(
                ctx,
                &alerts::SocketConnect::new_ipv6(ctx.pid(), binprm_inode, addr),
                0,
            );
            Action::Deny
        }
        action => action,
    }
}

#[inline(always)]
fn check_conditions<T, U, const V: usize>(
    map: &HashMap<u64, T>,
    addr: U,
    binprm_inode: u64,
    mode: Mode,
) -> Action
where
    T: IpAddrs<U, V>,
    U: Copy + PartialEq,
{
    if let Some(addrs) = unsafe { map.get(&INODE_WILDCARD) } {
        if let Some(action) = check_addresses(addrs, addr, &mode) {
            return action;
        }
    }

    if let Some(addrs) = unsafe { map.get(&binprm_inode) } {
        if let Some(action) = check_addresses(addrs, addr, &mode) {
            return action;
        }
    }

    match mode {
        Mode::Allowlist => Action::Deny,
        Mode::Denylist => Action::Allow,
    }
}

#[inline(always)]
fn check_addresses<T, U, const V: usize>(addrs: &T, addr: U, mode: &Mode) -> Option<Action>
where
    T: IpAddrs<U, V>,
    U: Copy + PartialEq,
{
    if addrs.all() {
        return Some(match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        });
    }

    if addrs.addrs()[..V].contains(&addr) {
        return Some(match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        });
    }

    None
}
