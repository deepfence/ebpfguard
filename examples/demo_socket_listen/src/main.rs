use std::{
    fs::{create_dir_all, remove_dir_all},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use ebpfguard::{policy::PolicySubject, PolicyManager};
use log::info;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "demo_socket_connect")]
    bpffs_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .build();
    log::set_max_level(logger.filter());
    log::set_boxed_logger(Box::from(logger)).context("Failed to set up logger")?;

    // Create a directory where ebpfguard policy manager can store its BPF
    // objects (maps).
    let bpf_path = opt.bpffs_path.join(opt.bpffs_dir);
    create_dir_all(&bpf_path)?;

    let mut policy_manager =
        PolicyManager::new(&bpf_path).context("couldn't create policy manager")?;

    let mut socket_bind = policy_manager
        .attach_socket_bind()
        .context("couldn't load eBPF bytecode to kernel")?;

    let mut rx = socket_bind
        .alerts()
        .await
        .context("couldn't get notifications channel for bind events")?;

    let policy = ebpfguard::policy::SocketBind {
        subject: PolicySubject::All,
        allow: ebpfguard::policy::Ports::All,
        deny: ebpfguard::policy::Ports::Ports(vec![8000]),
    };
    socket_bind
        .add_policy(policy)
        .await
        .context("failed to install policy")?;

    info!("Will block next 4 attempts to listen on a port 8000");

    for i in 0..4 {
        if let Some(alert) = rx.recv().await {
            info!(
                "socket_bind: pid={} subject={} port={}, count: {}",
                alert.pid, alert.subject, alert.port, i
            );
        }
    }

    info!("Exiting...");
    remove_dir_all(&bpf_path).context("Failed to clean up bpf maps directory")?;

    Ok(())
}
