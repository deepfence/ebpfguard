use anyhow::Context;
use ebpfguard::{
    policy::{PolicySubject, SbMount},
    PolicyManager,
};
use log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .build();
    log::set_max_level(logger.filter());
    log::set_boxed_logger(Box::from(logger)).context("Failed to set up logger")?;

    // Create a directory where ebpfguard policy manager can store its BPF
    // objects (maps).
    const BPF_MAPS_PATH: &str = "/sys/fs/bpf/example_sb_mount";
    std::fs::create_dir_all(BPF_MAPS_PATH)?;

    // Create a policy manager object.
    let mut policy_manager = PolicyManager::new(BPF_MAPS_PATH)?;

    // Attach the policy manager to the mount LSM hook.
    // This instruction loads bytecode into kernel.
    let mut sb_mount = policy_manager.attach_sb_mount()?;

    // Get the channel to which eBPF program attached to `file_open` lsm hook
    // will send notifications to.
    let mut sb_mount_rx = sb_mount.alerts().await?;

    // Define policies which deny mount operations for all processes (except
    // for the specified subject, if defined).
    sb_mount
        .add_policy(SbMount {
            subject: PolicySubject::All,
            allow: false,
        })
        .await?;

    if let Some(alert) = sb_mount_rx.recv().await {
        info!(
            "sb_mount alert: pid={} subject={}",
            alert.pid, alert.subject
        );
    }

    Ok(())
}
