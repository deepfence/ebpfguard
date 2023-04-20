use std::fs::create_dir_all;
use std::path::PathBuf;

use aya::maps::{AsyncPerfEventArray, MapData};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, BpfLoader};
use aya::{programs::Lsm, Btf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use guardity_common::{
    AlertSocketConnectV4, AlertSocketConnectV6, FileOpenAlert, SetuidAlert, SocketBindAlert,
};
use log::{info, warn};
use serde::Serialize;
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

async fn read_alerts<T>(mut map: AsyncPerfEventArray<MapData>)
where
    T: Serialize + Send + Sync + 'static,
{
    let cpus = online_cpus().unwrap();
    for cpu_id in cpus {
        let mut buf = map.open(cpu_id, None).unwrap();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const T;
                    let data = unsafe { ptr.read_unaligned() };
                    eprintln!("{}", serde_json::to_string(&data).unwrap());
                }
            }
        });
    }
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
    let programs = vec![
        "file_open",
        "task_fix_setuid",
        "socket_bind",
        "socket_connect",
    ];
    for name in programs {
        let program: &mut Lsm = bpf.program_mut(name).unwrap().try_into()?;
        program.load(name, &btf)?;
        program.attach()?;
    }

    for p in opt.policy {
        let policies = reader::read_policies(p)?;
        for policy in policies {
            engine::process_policy(&mut bpf, policy)?;
        }
    }

    read_alerts::<FileOpenAlert>(bpf.take_map("ALERT_FILE_OPEN").unwrap().try_into()?).await;
    read_alerts::<SetuidAlert>(bpf.take_map("ALERT_SETUID").unwrap().try_into()?).await;
    read_alerts::<SocketBindAlert>(bpf.take_map("ALERT_SOCKET_BIND").unwrap().try_into()?).await;
    read_alerts::<AlertSocketConnectV4>(
        bpf.take_map("ALERT_SOCKET_CONNECT_V4")
            .unwrap()
            .try_into()?,
    )
    .await;
    read_alerts::<AlertSocketConnectV6>(
        bpf.take_map("ALERT_SOCKET_CONNECT_V6")
            .unwrap()
            .try_into()?,
    )
    .await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
