use ebpfguard::{
    policy::{PolicySubject, SbMount},
    PolicyManager,
};
use log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    const BPF_MAPS_PATH: &str = "/sys/fs/bpf/example_sb_mount";

    // Create a directory where ebpfguard policy manager can store its BPF
    // objects (maps).
    std::fs::create_dir_all(BPF_MAPS_PATH)?;

    // Create a policy manager.
    let mut policy_manager = PolicyManager::new(BPF_MAPS_PATH)?;

    // Attach the policy manager to the mount LSM hook.
    let mut sb_mount = policy_manager.attach_sb_mount()?;

    // Get the receiver end of the alerts channel (for the `file_open` LSM
    // hook).
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
