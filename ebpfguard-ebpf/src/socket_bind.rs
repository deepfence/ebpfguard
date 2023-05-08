use aya_bpf::{cty::c_long, programs::LsmContext, BpfContext};
use ebpfguard_common::{alerts, consts::INODE_WILDCARD, policy::MAX_PORTS};

use crate::{
    binprm::current_binprm_inode,
    consts::AF_INET,
    maps::{ALERT_SOCKET_BIND, ALLOWED_SOCKET_BIND, DENIED_SOCKET_BIND},
    vmlinux::{sockaddr, sockaddr_in},
    Action,
};

/// Inspects the context of `socket_bind` LSM hook and decides whether to allow
/// or deny the bind operation based on the state of the `ALLOWED_SOCKET_BIND`
/// and `DENIED_SOCKET_BIND` maps.
///
/// If denied, the operation is logged to the `ALERT_SOCKET_BIND` map.
///
/// # Example
///
/// ```rust
/// use aya_bpf::{macros::lsm, programs::LsmContext};
/// use ebpfguard_ebpf::socket_bind;
///
/// #[lsm(name = "my_program")]
/// pub fn my_program(ctx: LsmContext) -> i32 {
///     match socket_bind::socket_bind(ctx) {
///         Ok(ret) => ret,
///         Err(_) => 0,
///     }
/// }
/// ```
#[inline(always)]
pub fn socket_bind(ctx: LsmContext) -> Result<Action, c_long> {
    let sockaddr: *const sockaddr = unsafe { ctx.arg(1) };

    if unsafe { (*sockaddr).sa_family } != AF_INET {
        return Ok(Action::Allow);
    }

    let sockaddr_in: *const sockaddr_in = sockaddr as *const sockaddr_in;
    let port = u16::from_be(unsafe { (*sockaddr_in).sin_port });

    if port == 0 {
        return Ok(Action::Allow);
    }

    let binprm_inode = current_binprm_inode()?;

    if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&INODE_WILDCARD) } {
        if ports.all() {
            if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&INODE_WILDCARD) } {
                if ports.all() {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(Action::Deny);
                }
                if ports.ports[..MAX_PORTS - 1].contains(&port) {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(Action::Deny);
                }
            }

            if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&binprm_inode) } {
                if ports.all() {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(Action::Deny);
                }
                if ports.ports[..MAX_PORTS - 1].contains(&port) {
                    ALERT_SOCKET_BIND.output(
                        &ctx,
                        &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                        0,
                    );
                    return Ok(Action::Deny);
                }
            }
        } else {
            if ports.ports[..MAX_PORTS - 1].contains(&port) {
                return Ok(Action::Allow);
            }
        }
    }

    if let Some(ports) = unsafe { DENIED_SOCKET_BIND.get(&INODE_WILDCARD) } {
        if ports.all() {
            if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&INODE_WILDCARD) } {
                if ports.all() {
                    return Ok(Action::Allow);
                }
                if ports.ports[..MAX_PORTS - 1].contains(&port) {
                    return Ok(Action::Allow);
                }
            }

            if let Some(ports) = unsafe { ALLOWED_SOCKET_BIND.get(&binprm_inode) } {
                if ports.all() {
                    return Ok(Action::Allow);
                }
                if ports.ports[..MAX_PORTS - 1].contains(&port) {
                    return Ok(Action::Allow);
                }
            }

            ALERT_SOCKET_BIND.output(
                &ctx,
                &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                0,
            );
            return Ok(Action::Deny);
        } else {
            if ports.ports[..MAX_PORTS - 1].contains(&port) {
                ALERT_SOCKET_BIND.output(
                    &ctx,
                    &alerts::SocketBind::new(ctx.pid(), binprm_inode, port),
                    0,
                );
                return Ok(Action::Deny);
            }
        }
    }

    Ok(Action::Allow)
}
