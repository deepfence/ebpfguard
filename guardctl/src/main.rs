use std::{collections::HashSet, path::PathBuf};

use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapError},
    Bpf, BpfLoader,
};
use clap::{Parser, Subcommand};
use cli_table::{print_stdout, Cell, Style, Table, TableStruct};
use guardity::policy::{
    engine::{self, INODE_WILDCARD},
    reader, Paths, Ports,
};

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "guardity")]
    bpffs_dir: PathBuf,
    #[command(subcommand)]
    subcommand: Sub,
}

#[derive(Subcommand)]
enum Sub {
    /// Manage policies.
    Policy {
        #[command(subcommand)]
        policy: SubPolicy,
    },
}

#[derive(Subcommand)]
enum SubPolicy {
    /// Add policies.
    Add {
        #[clap(long)]
        r#path: PathBuf,
    },
    /// List policies.
    List,
}

fn add_policies(bpf: &mut Bpf, r#path: PathBuf) -> anyhow::Result<()> {
    let policies = reader::read_policies(r#path)?;
    for policy in policies {
        engine::process_policy(bpf, policy)?;
    }
    Ok(())
}

fn list_file_open(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
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

fn list_setuid(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_setuid: HashMap<_, u64, u8> = bpf.map("ALLOWED_SETUID").unwrap().try_into()?;
    for res in allowed_setuid.iter() {
        let (inode, _) = res?;
        if inode == INODE_WILDCARD {
            table.push(vec!["allow".to_string(), "all".to_string()]);
        } else {
            table.push(vec!["allow".to_string(), inode.to_string()]);
        }
    }

    let denied_setuid: HashMap<_, u64, u8> = bpf.map("DENIED_SETUID").unwrap().try_into()?;
    for res in denied_setuid.iter() {
        let (inode, _) = res?;
        if inode == INODE_WILDCARD {
            table.push(vec!["deny".to_string(), "all".to_string()]);
        } else {
            table.push(vec!["deny".to_string(), inode.to_string()]);
        }
    }

    let table = table.table().title(vec![
        "action".cell().bold(true),
        "subject".cell().bold(true),
    ]);

    Ok(table)
}

fn list_socket_bind(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_socket_connect: HashMap<_, u64, guardity_common::Ports> =
        bpf.map("ALLOWED_SOCKET_CONNECT").unwrap().try_into()?;
    let denied_socket_connect: HashMap<_, u64, guardity_common::Ports> =
        bpf.map("DENIED_SOCKET_CONNECT").unwrap().try_into()?;

    let mut subjects = HashSet::new();
    for key in allowed_socket_connect.keys() {
        let key = key?;
        subjects.insert(key);
    }
    for key in denied_socket_connect.keys() {
        let key = key?;
        subjects.insert(key);
    }

    for subject in subjects {
        let allowed = match allowed_socket_connect.get(&subject, 0) {
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
        let denied = match denied_socket_connect.get(&subject, 0) {
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

fn list_policies(bpf: &mut Bpf) -> anyhow::Result<()> {
    let file_open = list_file_open(bpf)?;
    let setuid = list_setuid(bpf)?;
    let socket_bind = list_socket_bind(bpf)?;

    let table = vec![
        vec!["file_open".cell()],
        vec![file_open.display()?.cell()],
        vec!["setuid".cell()],
        vec![setuid.display()?.cell()],
        vec!["socket_bind".cell()],
        vec![socket_bind.display()?.cell()],
    ]
    .table()
    .title(vec!["Policy".cell().bold(true)]);

    print_stdout(table)?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let bpf_path = args.bpffs_path.join(args.bpffs_dir);

    match args.subcommand {
        Sub::Policy { policy } => {
            #[cfg(debug_assertions)]
            let mut bpf = BpfLoader::new()
                .map_pin_path(bpf_path)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/debug/guardity"
                ))?;
            #[cfg(not(debug_assertions))]
            let mut bpf = BpfLoader::new()
                .map_pin_path(bpf_path)
                .load(include_bytes_aligned!(
                    "../../target/bpfel-unknown-none/release/guardity"
                ))?;
            match policy {
                SubPolicy::Add { r#path } => {
                    add_policies(&mut bpf, path)?;
                }
                SubPolicy::List => {
                    list_policies(&mut bpf)?;
                }
            }
        }
    }

    Ok(())
}
