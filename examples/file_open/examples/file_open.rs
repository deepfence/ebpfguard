use std::{fs::create_dir_all, path::PathBuf};

use clap::Parser;
use guardity::{
    policy::{FileOpen, Paths, PolicySubject},
    PolicyManager,
};
use log::info;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "example_file_open")]
    bpffs_dir: PathBuf,
    /// Binary which should be the subject of the policy. If empty, all
    /// processes are subject.
    #[clap(long)]
    subject: Option<PathBuf>,
    /// Path to which the open access should be denied.
    #[clap(long)]
    path_to_deny: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Create a directory where guardity policy manager can store its BPF
    // objects (maps).
    let bpf_path = opt.bpffs_path.join(opt.bpffs_dir);
    create_dir_all(&bpf_path)?;

    // Create a policy manager.
    let mut policy_manager = PolicyManager::new(bpf_path)?;

    // Attach the policy manager to the `file_open` LSM hook.
    let mut file_open = policy_manager.attach_file_open()?;

    // Get the receiver end of the alerts channel (for the `file_open` LSM
    // hook).
    let mut rx = file_open.alerts().await?;

    // Based on input from CLI, decide whether the policy subject is a certain
    // binary or all processes.
    let subject = match opt.subject {
        Some(subject) => PolicySubject::Binary(subject),
        None => PolicySubject::All,
    };

    // Define a policy which blocks access to a provided path.
    let policy = FileOpen {
        subject,
        allow: Paths::All,
        deny: Paths::Paths(vec![opt.path_to_deny]),
    };

    // Add the policy to the policy manager.
    file_open.add_policy(policy).await?;

    info!("Waiting for Ctrl-C...");

    // Wait for policy violation alerts (or for CTRL+C).
    loop {
        tokio::select! {
            Some(alert) = rx.recv() => {
                info!("file_open: pid={} subject={} path={}", alert.pid, alert.subject, alert.path.display());
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}
