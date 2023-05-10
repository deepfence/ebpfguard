use std::{fs, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use ebpfguard::{
    policy::{PolicySubject, Ports, SocketBind},
    PolicyManager,
};
use log::info;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "demo_socket_connect")]
    bpffs_dir: PathBuf,
    #[clap(long)]
    deny: Vec<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .build();
    log::set_max_level(logger.filter());
    log::set_boxed_logger(Box::from(logger)).context("Failed to set up logger")?;

    let bpf_path: PathBuf = opt.bpffs_path.join(opt.bpffs_dir);
    fs::create_dir_all(&bpf_path)?;

    let mut policy_manager =
        PolicyManager::new(&bpf_path).context("kernel verifier rejected eBPF hooks object file")?;

    let mut socket_bind = policy_manager
        .attach_socket_bind()
        .context("couldn't attach socket_bind hook")?;

    let mut rx = socket_bind
        .alerts()
        .await
        .context("couldn't get alerts channel for bind events")?;

    let policy = SocketBind {
        subject: PolicySubject::All,
        allow: Ports::All,
        deny: Ports::Ports(opt.deny.clone()),
    };

    socket_bind
        .add_policy(policy)
        .await
        .context("failed to add policy")?;

    info!(
        "Will block next 4 attempts to listen on a ports {:?}",
        opt.deny
    );

    for i in 0..4 {
        if let Some(alert) = rx.recv().await {
            info!(
                "socket_bind: pid={} subject={} port={}, count: {}",
                alert.pid, alert.subject, alert.port, i
            );
        }
    }

    info!("Exiting...");
    fs::remove_dir_all(&bpf_path).context("Failed to clean up bpf maps directory")?;

    Ok(())
}
