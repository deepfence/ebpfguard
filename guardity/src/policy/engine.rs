use aya::{maps::HashMap, Bpf};
use guardity_common::{Ipv4Addrs, Ipv6Addrs, Paths, Ports};

use super::{Policy, PolicySubject};
use crate::fs;

pub const INODE_WILDCARD: u64 = 0;

pub fn process_policy(bpf: &mut Bpf, policy: Policy) -> anyhow::Result<()> {
    match policy {
        Policy::FileOpen {
            subject,
            allow,
            deny,
        } => {
            let allow: Paths = allow.into();
            let deny: Paths = deny.into();
            match subject {
                PolicySubject::Process(path) => {
                    let bin_inode = fs::inode(path)?;

                    let mut allowed_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("ALLOWED_FILE_OPEN").unwrap().try_into()?;
                    allowed_file_open.insert(bin_inode, allow, 0)?;

                    let mut denied_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("DENIED_FILE_OPEN").unwrap().try_into()?;
                    denied_file_open.insert(bin_inode, deny, 0)?;
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    let mut allowed_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("ALLOWED_FILE_OPEN").unwrap().try_into()?;
                    allowed_file_open.insert(INODE_WILDCARD, allow, 0)?;

                    let mut denied_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("DENIED_FILE_OPEN").unwrap().try_into()?;
                    denied_file_open.insert(INODE_WILDCARD, deny, 0)?;
                }
            }
        }
        Policy::SetUid { subject, allow } => {
            match subject {
                PolicySubject::Process(path) => {
                    let inode = fs::inode(path)?;
                    if allow {
                        let mut allowed_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;
                        allowed_setuid.insert(inode, 0, 0)?;
                    } else {
                        let mut denied_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("DENIED_SETUID").unwrap().try_into()?;
                        denied_setuid.insert(inode, 0, 0)?;
                    }
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    if allow {
                        let mut allowed_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;
                        allowed_setuid.insert(INODE_WILDCARD, 0, 0)?;
                    } else {
                        let mut denied_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("DENIED_SETUID").unwrap().try_into()?;
                        denied_setuid.insert(INODE_WILDCARD, 0, 0)?;
                    }
                }
            };
        }
        Policy::SocketBind {
            subject,
            allow,
            deny,
        } => {
            let allow: Ports = allow.into();
            let deny: Ports = deny.into();
            match subject {
                PolicySubject::Process(path) => {
                    let inode = fs::inode(path)?;
                    let mut allowed_socket_bind: HashMap<_, u64, Ports> =
                        bpf.map_mut("ALLOWED_SOCKET_BIND").unwrap().try_into()?;
                    allowed_socket_bind.insert(inode, allow, 0)?;

                    let mut denied_socket_bind: HashMap<_, u64, Ports> =
                        bpf.map_mut("DENIED_SOCKET_BIND").unwrap().try_into()?;
                    denied_socket_bind.insert(inode, deny, 0)?;
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    let mut allowed_socket_bind: HashMap<_, u64, Ports> =
                        bpf.map_mut("ALLOWED_SOCKET_BIND").unwrap().try_into()?;
                    allowed_socket_bind.insert(INODE_WILDCARD, allow, 0)?;

                    let mut denied_socket_bind: HashMap<_, u64, Ports> =
                        bpf.map_mut("DENIED_SOCKET_BIND").unwrap().try_into()?;
                    denied_socket_bind.insert(INODE_WILDCARD, deny, 0)?;
                }
            }
        }
        Policy::SocketConnect {
            subject,
            allow,
            deny,
        } => {
            let (allow_v4, allow_v6) = allow.into_ebpf();
            let (deny_v4, deny_v6) = deny.into_ebpf();
            match subject {
                PolicySubject::Process(bin_path) => {
                    let bin_inode = fs::inode(bin_path)?;

                    let mut allowed_socket_connect_v4: HashMap<_, u64, Ipv4Addrs> = bpf
                        .map_mut("ALLOWED_SOCKET_CONNECT_V4")
                        .unwrap()
                        .try_into()?;
                    allowed_socket_connect_v4.insert(bin_inode, allow_v4, 0)?;

                    let mut denied_socket_connect_v4: HashMap<_, u64, Ipv4Addrs> = bpf
                        .map_mut("DENIED_SOCKET_CONNECT_V4")
                        .unwrap()
                        .try_into()?;
                    denied_socket_connect_v4.insert(bin_inode, deny_v4, 0)?;

                    let mut allowed_socket_connect_v6: HashMap<_, u64, Ipv6Addrs> = bpf
                        .map_mut("ALLOWED_SOCKET_CONNECT_V6")
                        .unwrap()
                        .try_into()?;
                    allowed_socket_connect_v6.insert(bin_inode, allow_v6, 0)?;

                    let mut denied_socket_connect_v6: HashMap<_, u64, Ipv6Addrs> = bpf
                        .map_mut("DENIED_SOCKET_CONNECT_V6")
                        .unwrap()
                        .try_into()?;
                    denied_socket_connect_v6.insert(bin_inode, deny_v6, 0)?;
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    let mut allowed_socket_connect_v4: HashMap<_, u64, Ipv4Addrs> = bpf
                        .map_mut("ALLOWED_SOCKET_CONNECT_V4")
                        .unwrap()
                        .try_into()?;
                    allowed_socket_connect_v4.insert(INODE_WILDCARD, allow_v4, 0)?;

                    let mut denied_socket_connect_v4: HashMap<_, u64, Ipv4Addrs> = bpf
                        .map_mut("DENIED_SOCKET_CONNECT_V4")
                        .unwrap()
                        .try_into()?;
                    denied_socket_connect_v4.insert(INODE_WILDCARD, deny_v4, 0)?;

                    let mut allowed_socket_connect_v6: HashMap<_, u64, Ipv6Addrs> = bpf
                        .map_mut("ALLOWED_SOCKET_CONNECT_V6")
                        .unwrap()
                        .try_into()?;
                    allowed_socket_connect_v6.insert(INODE_WILDCARD, allow_v6, 0)?;

                    let mut denied_socket_connect_v6: HashMap<_, u64, Ipv6Addrs> = bpf
                        .map_mut("DENIED_SOCKET_CONNECT_V6")
                        .unwrap()
                        .try_into()?;
                    denied_socket_connect_v6.insert(INODE_WILDCARD, deny_v6, 0)?;
                }
            }
        }
    }
    Ok(())
}
