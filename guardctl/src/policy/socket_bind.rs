use std::collections::HashSet;

use aya::{
    maps::{HashMap, MapError},
    Bpf,
};
use cli_table::{Cell, Style, Table, TableStruct};
use guardity::policy::{engine::INODE_WILDCARD, Ports};

pub(crate) fn list_socket_bind(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_socket_bind: HashMap<_, u64, guardity_common::Ports> =
        bpf.map("ALLOWED_SOCKET_BIND").unwrap().try_into()?;
    let denied_socket_bind: HashMap<_, u64, guardity_common::Ports> =
        bpf.map("DENIED_SOCKET_BIND").unwrap().try_into()?;

    let mut subjects = HashSet::new();
    for key in allowed_socket_bind.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in denied_socket_bind.keys() {
        let key = key?;
        subjects.insert(key);
    }

    for subject in subjects {
        let allowed = match allowed_socket_bind.get(&subject, 0) {
            Ok(allowed) => {
                let allowed = allowed.into();
                match allowed {
                    Ports::All => "all".to_owned(),
                    Ports::Ports(ports) => ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                }
            }
            Err(MapError::KeyNotFound) => "-".to_owned(),
            Err(e) => return Err(e.into()),
        };
        let denied = match denied_socket_bind.get(&subject, 0) {
            Ok(denied) => {
                let denied = denied.into();
                match denied {
                    Ports::All => "all".to_owned(),
                    Ports::Ports(ports) => ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                }
            }
            Err(MapError::KeyNotFound) => "-".to_owned(),
            Err(e) => return Err(e.into()),
        };
        if subject == INODE_WILDCARD {
            table.push(vec!["all".to_string(), allowed, denied]);
        } else {
            table.push(vec![subject.to_string(), allowed, denied]);
        }
    }

    let table = table.table().title(vec![
        "subject".cell().bold(true),
        "allowed ports".cell().bold(true),
        "denied ports".cell().bold(true),
    ]);

    Ok(table)
}
