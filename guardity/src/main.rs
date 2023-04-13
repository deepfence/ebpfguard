use std::fs::create_dir_all;
use std::path::PathBuf;

use aya::{include_bytes_aligned, BpfLoader};
use aya::{programs::Lsm, Btf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use guardity::policy::{engine, reader};

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let bpf_path = opt.bpffs_path.join(opt.bpffs_dir);
    create_dir_all(&bpf_path)?;
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .map_pin_path(&bpf_path)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/guardity"
        ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .map_pin_path(&bpf_path)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/guardity"
        ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("task_fix_setuid").unwrap().try_into()?;
    program.load("task_fix_setuid", &btf)?;
    program.attach()?;
    let program: &mut Lsm = bpf.program_mut("socket_recvmsg").unwrap().try_into()?;
    program.load("socket_recvmsg", &btf)?;
    program.attach()?;

    for p in opt.policy {
        let policies = reader::read_policies(p)?;
        for policy in policies {
            engine::process_policy(&mut bpf, policy)?;
        }
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
