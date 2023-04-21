use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use aya::{maps::HashMap, Bpf};
use cli_table::{Cell, Style, Table, TableStruct};
use guardity::policy::engine::INODE_WILDCARD;

enum Addresses {
    All,
    Addresses(Vec<IpAddr>),
}

pub(crate) fn list_socket_connect(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_socket_connect_v4: HashMap<_, u64, guardity_common::Ipv4Addrs> =
        bpf.map("ALLOWED_SOCKET_CONNECT_V4").unwrap().try_into()?;
    let denied_socket_connect_v4: HashMap<_, u64, guardity_common::Ipv4Addrs> =
        bpf.map("DENIED_SOCKET_CONNECT_V4").unwrap().try_into()?;
    let allowed_socket_connect_v6: HashMap<_, u64, guardity_common::Ipv6Addrs> =
        bpf.map("ALLOWED_SOCKET_CONNECT_V6").unwrap().try_into()?;
    let denied_socket_connect_v6: HashMap<_, u64, guardity_common::Ipv6Addrs> =
        bpf.map("DENIED_SOCKET_CONNECT_V6").unwrap().try_into()?;

    let mut subjects = HashSet::new();
    for key in allowed_socket_connect_v4.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in denied_socket_connect_v4.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in allowed_socket_connect_v6.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in denied_socket_connect_v6.keys() {
        let key = key?;
        subjects.insert(key);
    }

    for subject in subjects {
        let mut allowed = match allowed_socket_connect_v4.get(&subject, 0) {
            Ok(allowed) => {
                if allowed.all() {
                    Addresses::All
                } else {
                    Addresses::Addresses(
                        allowed
                            .addrs
                            .iter()
                            .map(|a| IpAddr::V4(Ipv4Addr::from(*a)))
                            .collect(),
                    )
                }
            }
            Err(aya::maps::MapError::KeyNotFound) => Addresses::Addresses(vec![]),
            Err(e) => return Err(e.into()),
        };
        if let Addresses::Addresses(addrs) = &mut allowed {
            match allowed_socket_connect_v6.get(&subject, 0) {
                Ok(allowed) => {
                    if allowed.all() {
                        anyhow::bail!("Inconsistent policies: allowed all IPv6 addresses, but specified IPv4 addresses")
                    } else {
                        addrs.extend(allowed.addrs.iter().map(|a| IpAddr::V6(Ipv6Addr::from(*a))));
                    }
                }
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let mut denied = match denied_socket_connect_v4.get(&subject, 0) {
            Ok(denied) => {
                if denied.all() {
                    Addresses::All
                } else {
                    Addresses::Addresses(
                        denied
                            .addrs
                            .iter()
                            .map(|a| IpAddr::V4(Ipv4Addr::from(*a)))
                            .collect(),
                    )
                }
            }
            Err(aya::maps::MapError::KeyNotFound) => Addresses::Addresses(vec![]),
            Err(e) => return Err(e.into()),
        };
        if let Addresses::Addresses(addrs) = &mut denied {
            match denied_socket_connect_v6.get(&subject, 0) {
                Ok(denied) => {
                    if denied.all() {
                        anyhow::bail!("Inconsistent policies: denied all IPv6 addresses, but specified IPv4 addresses")
                    } else {
                        addrs.extend(denied.addrs.iter().map(|a| IpAddr::V6(Ipv6Addr::from(*a))));
                    }
                }
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let allowed = match allowed {
            Addresses::All => "all".to_owned(),
            Addresses::Addresses(addrs) => addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let denied = match denied {
            Addresses::All => "all".to_owned(),
            Addresses::Addresses(addrs) => addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };

        if subject == INODE_WILDCARD {
            table.push(vec!["all".to_owned(), allowed, denied]);
        } else {
            table.push(vec![subject.to_string(), allowed, denied]);
        }
    }

    let table = table.table().title(vec![
        "Subject".cell().bold(true),
        "Allowed".cell().bold(true),
        "Denied".cell().bold(true),
    ]);
    Ok(table)
}
