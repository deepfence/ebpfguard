use std::path::PathBuf;

use aya::{include_bytes_aligned, BpfLoader};
use clap::{Parser, Subcommand};
use policy::{add_policies, list_policies};

mod policy;

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
