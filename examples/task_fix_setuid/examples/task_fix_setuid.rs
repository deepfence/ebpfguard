use std::{
    fs::{create_dir_all, remove_dir_all},
    path::PathBuf,
};

use clap::Parser;
use ebpfguard::{
    policy::{PolicySubject, TaskFixSetuid},
    PolicyManager,
};
use log::info;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "example_task_fix_setuid")]
    bpffs_dir: PathBuf,
    /// Binary which should be allowed to change UID.
    #[clap(long)]
    allow: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Create a directory where ebpfguard policy manager can store its BPF
    // objects (maps).
    let bpf_path = opt.bpffs_path.join(opt.bpffs_dir);
    create_dir_all(&bpf_path)?;

    // Create a policy manager.
    let mut policy_manager = PolicyManager::new(&bpf_path)?;

    // Attach the policy manager to the `task_fix_setuid` LSM hook.
    let mut task_fix_setuid = policy_manager.attach_task_fix_setuid()?;

    // Get the receiver end of the alerts channel (for the `file_open` LSM
    // hook).
    let mut rx = task_fix_setuid.alerts().await?;

    // Define policies which deny setuid for all processes (except for the
    // specified subject, if defined).
    let wildcard_deny_policy = TaskFixSetuid {
        subject: PolicySubject::All,
        allow: false,
    };
    task_fix_setuid.add_policy(wildcard_deny_policy).await?;
    if let Some(subject) = opt.allow {
        let subject_allow_policy = TaskFixSetuid {
            subject: PolicySubject::Binary(subject),
            allow: true,
        };
        task_fix_setuid.add_policy(subject_allow_policy).await?;
    }

    info!("Waiting for Ctrl-C...");

    // Wait for policy violation alerts (or for CTRL+C).
    loop {
        tokio::select! {
            Some(alert) = rx.recv() => {
                info!(
                    "file_open: pid={} subject={} old_uid={} old_gid={} new_uid={} new_gid={}",
                    alert.pid,
                    alert.subject,
                    alert.old_uid,
                    alert.old_gid,
                    alert.new_uid,
                    alert.new_gid
                );
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    info!("Exiting...");
    remove_dir_all(&bpf_path)?;

    Ok(())
}
