use std::fs::create_dir_all;
use std::path::PathBuf;

use clap::Parser;
use guardity::PolicyManager;
use log::info;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "guardity")]
    bpffs_dir: PathBuf,
    #[clap(long)]
    policy: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let bpf_path = opt.bpffs_path.join(opt.bpffs_dir);
    create_dir_all(&bpf_path)?;

    let mut policy_manager = PolicyManager::new(bpf_path)?;

    policy_manager.attach_bprm_check_security()?;
    policy_manager.attach_file_open()?;
    policy_manager.attach_task_fix_setuid()?;
    policy_manager.attach_socket_bind()?;
    policy_manager.attach_socket_connect()?;

    let mut rx_bprm_check_security = policy_manager.bprm_check_security()?.alerts().await?;
    let mut rx_file_open = policy_manager.file_open()?.alerts().await?;
    let mut rx_task_fix_setuid = policy_manager.task_fix_setuid()?.alerts().await?;
    let mut rx_socket_bind = policy_manager.socket_bind()?.alerts().await?;
    let mut rx_socket_connect = policy_manager.socket_connect()?.alerts().await?;

    info!("Waiting for Ctrl-C...");

    loop {
        tokio::select! {
            Some(alert) = rx_bprm_check_security.recv() => {
                info!("bprm_check_security: {}", alert.pid);
            }
            Some(alert) = rx_file_open.recv() => {
                info!("file_open: {}", alert.pid);
            }
            Some(alert) = rx_task_fix_setuid.recv() => {
                info!("task_fix_setuid: pid={} binprm_inode={}", alert.pid, alert.binprm_inode);
            }
            Some(alert) = rx_socket_bind.recv() => {
                info!("socket_bind: pid={}", alert.pid);
            }
            Some(alert) = rx_socket_connect.recv() => {
                if alert.addr_v4 != 0 {
                    info!(
                        "socket_connect: pid={} binprm_inode={} addr={}",
                        alert.pid,
                        alert.binprm_inode,
                        alert.addr_v4
                    );
                } else {
                    info!(
                        "socket_connect: pid={} binprm_inode={} addr={:?}",
                        alert.pid,
                        alert.binprm_inode,
                        alert.addr_v6
                    );
                }
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    info!("Exiting...");

    Ok(())
}
