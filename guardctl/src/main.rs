use std::path::PathBuf;

use clap::{Parser, Subcommand};
use guardity::PolicyManager;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let bpf_path = args.bpffs_path.join(args.bpffs_dir);

    match args.subcommand {
        Sub::Policy { policy } => {
            let mut policy_manager = PolicyManager::new(bpf_path)?;

            match policy {
                SubPolicy::Add { r#path } => {
                    add_policies(&mut policy_manager, path).await?;
                }
                SubPolicy::List => {
                    list_policies(&mut policy_manager).await?;
                }
            }
        }
    }

    Ok(())
}
