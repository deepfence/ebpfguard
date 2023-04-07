use std::path::PathBuf;

use aya::{include_bytes_aligned, maps::HashMap, Bpf, BpfLoader};
use clap::{Parser, Subcommand};
use cli_table::{print_stdout, Cell, Style, Table};
use guardity::policy::{engine, reader};

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

fn list_policies(bpf: &mut Bpf) -> anyhow::Result<()> {
    let mut table = Vec::new();

    let allowed_setuid: HashMap<_, u64, u8> = bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;

    for res in allowed_setuid.iter() {
        let (inode, _) = res?;
        table.push(vec!["allow".to_string(), inode.to_string()]);
    }

    let table = table.table().title(vec![
        "action".cell().bold(true),
        "subject".cell().bold(true),
    ]);

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
