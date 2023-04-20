use std::fs::create_dir_all;
use std::path::PathBuf;

use aya::maps::{AsyncPerfEventArray, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
use guardity::PolicyManager;
use guardity_common::{AlertFileOpen, AlertSetuid, AlertSocketBind, AlertSocketConnect};
use log::info;
use serde::Serialize;
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

    let mut policy_manager = PolicyManager::new(bpf_path)?;
    policy_manager.attach_file_open()?;
    policy_manager.attach_task_fix_setuid()?;
    policy_manager.attach_socket_bind()?;
    policy_manager.attach_socket_connect()?;

    read_alerts::<AlertFileOpen>(
        policy_manager
            .bpf
            .take_map("ALERT_FILE_OPEN")
            .unwrap()
            .try_into()?,
    )
    .await;
    read_alerts::<AlertSetuid>(
        policy_manager
            .bpf
            .take_map("ALERT_SETUID")
            .unwrap()
            .try_into()?,
    )
    .await;
    read_alerts::<AlertSocketBind>(
        policy_manager
            .bpf
            .take_map("ALERT_SOCKET_BIND")
            .unwrap()
            .try_into()?,
    )
    .await;
    read_alerts::<AlertSocketConnect>(
        policy_manager
            .bpf
            .take_map("ALERT_SOCKET_CONNECT")
            .unwrap()
            .try_into()?,
    )
    .await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
