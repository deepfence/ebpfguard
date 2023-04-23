use std::{
    fs::{create_dir_all, remove_dir_all},
    path::PathBuf,
};

use clap::Parser;
use ebpfguard::{
    policy::{PolicySubject, SbMount, SbRemount, SbUmount},
    PolicyManager,
};
use log::info;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "/sys/fs/bpf")]
    bpffs_path: PathBuf,
    #[clap(long, default_value = "example_sb_mount")]
    bpffs_dir: PathBuf,
    /// Binary which should be allowed to mount filesystems.
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

    // Attach the policy manager to the mount LSM hooks.
    let mut sb_mount = policy_manager.attach_sb_mount()?;
    let mut sb_remount = policy_manager.attach_sb_remount()?;
    let mut sb_umount = policy_manager.attach_sb_umount()?;

    // Get the receiver end of the alerts channel (for the `file_open` LSM
    // hook).
    let mut sb_mount_rx = sb_mount.alerts().await?;
    let mut sb_remount_rx = sb_remount.alerts().await?;
    let mut sb_umount_rx = sb_umount.alerts().await?;

    // Define policies which deny mount operations for all processes (except
    // for the specified subject, if defined).
    sb_mount
        .add_policy(SbMount {
            subject: PolicySubject::All,
            allow: false,
        })
        .await?;
    sb_remount
        .add_policy(SbRemount {
            subject: PolicySubject::All,
            allow: false,
        })
        .await?;
    sb_umount
        .add_policy(SbUmount {
            subject: PolicySubject::All,
            allow: false,
        })
        .await?;
    if let Some(subject) = opt.allow {
        sb_mount
            .add_policy(SbMount {
                subject: PolicySubject::Binary(subject.clone()),
                allow: true,
            })
            .await?;
        sb_remount
            .add_policy(SbRemount {
                subject: PolicySubject::Binary(subject.clone()),
                allow: true,
            })
            .await?;
        sb_umount
            .add_policy(SbUmount {
                subject: PolicySubject::Binary(subject),
                allow: true,
            })
            .await?;
    }

    info!("Waiting for Ctrl-C...");

    // Wait for policy violation alerts (or for CTRL+C).
    loop {
        tokio::select! {
            Some(alert) = sb_mount_rx.recv() => {
                info!(
                    "sb_mount: pid={} subject={}",
                    alert.pid,
                    alert.subject,
                );
            }
            Some(alert) = sb_remount_rx.recv() => {
                info!(
                    "sb_remount: pid={} subject={}",
                    alert.pid,
                    alert.subject,
                );
            }
            Some(alert) = sb_umount_rx.recv() => {
                info!(
                    "sb_umount: pid={} subject={}",
                    alert.pid,
                    alert.subject,
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
