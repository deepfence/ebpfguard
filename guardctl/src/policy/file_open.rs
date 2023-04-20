use std::collections::HashSet;

use aya::{
    maps::{HashMap, MapError},
    Bpf,
};
use cli_table::{Cell, Style, Table, TableStruct};
use guardity::policy::{engine::INODE_WILDCARD, Paths};

pub(crate) fn list_file_open(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_file_open: HashMap<_, u64, guardity_common::Paths> =
        bpf.map("ALLOWED_FILE_OPEN").unwrap().try_into()?;
    let denied_file_open: HashMap<_, u64, guardity_common::Paths> =
        bpf.map("DENIED_FILE_OPEN").unwrap().try_into()?;

    let mut subjects = HashSet::new();
    for key in allowed_file_open.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in denied_file_open.keys() {
        let key = key?;
        subjects.insert(key);
    }

    for subject in subjects {
        let allowed = match allowed_file_open.get(&subject, 0) {
            Ok(allowed) => {
                let allowed = allowed.into();
                match allowed {
                    Paths::All => "all".to_owned(),
                    Paths::Paths(paths) => paths
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                }
            }
            Err(MapError::KeyNotFound) => "-".to_owned(),
            Err(e) => return Err(e.into()),
        };
        let denied = match denied_file_open.get(&subject, 0) {
            Ok(denied) => {
                let denied = denied.into();
                match denied {
                    Paths::All => "all".to_owned(),
                    Paths::Paths(paths) => paths
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
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
        "allowed paths".cell().bold(true),
        "denied paths".cell().bold(true),
    ]);

    Ok(table)
}
