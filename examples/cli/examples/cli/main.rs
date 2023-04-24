use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cli_table::{print_stdout, Cell, Style, Table};

mod file_open;
mod socket_bind;
mod socket_connect;
mod task_fix_setuid;

use ebpfguard::{policy::reader, PolicyManager};
use file_open::list_file_open;
use socket_bind::list_socket_bind;
use socket_connect::list_socket_connect;
use task_fix_setuid::list_task_fix_setuid;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "ebpfguard")]
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

async fn add_policies(policy_manager: &mut PolicyManager, r#path: PathBuf) -> anyhow::Result<()> {
    let mut all = policy_manager.manage_all()?;
    let policies = reader::read_policies(r#path)?;
    for policy in policies {
        all.add_policy(policy).await?;
    }
    Ok(())
}

async fn list_policies(policy_manager: &mut PolicyManager) -> anyhow::Result<()> {
    let file_open = list_file_open(policy_manager).await?;
    let setuid = list_task_fix_setuid(policy_manager).await?;
    let socket_bind = list_socket_bind(policy_manager).await?;
    let socket_connect = list_socket_connect(policy_manager).await?;

    let table = vec![
        vec!["file_open".cell()],
        vec![file_open.display()?.cell()],
        vec!["setuid".cell()],
        vec![setuid.display()?.cell()],
        vec!["socket_bind".cell()],
        vec![socket_bind.display()?.cell()],
        vec!["socket_connect".cell()],
        vec![socket_connect.display()?.cell()],
    ]
    .table()
    .title(vec!["Policy".cell().bold(true)]);

    print_stdout(table)?;

    Ok(())
}
