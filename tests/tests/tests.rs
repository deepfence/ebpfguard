use std::{net::IpAddr, os::unix::fs::MetadataExt, path::PathBuf, time::Duration};

use ebpfguard::{
    policy::{Addresses, PolicySubject, SocketConnect},
    PolicyManager,
};
use tokio::{net::TcpListener, sync::oneshot};

#[tokio::test]
async fn test_socket_connect_deny_all() {
    let (tx, rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let mut mgr: PolicyManager = PolicyManager::with_default_path().unwrap();

        let mut socket_connect = mgr.attach_socket_connect().unwrap();

        let mut rx = socket_connect.alerts().await.unwrap();

        println!("registering deny policy");
        socket_connect
            .add_policy(SocketConnect {
                subject: PolicySubject::All,
                allow: Addresses::All,
                deny: Addresses::Addresses(vec![IpAddr::from([127, 1, 2, 3])]),
            })
            .await
            .unwrap();

        tx.send(()).unwrap();
        println!("listening for alarms");

        while let Some(msg) = rx.recv().await {
            println!("alert found: {:?}", msg);
            if msg.addr == IpAddr::from([127, 1, 2, 3]) {
                break;
            }
        }
    });

    let _ = rx.await;

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.1.2.3:8080").await.unwrap();
        println!("listener started");

        loop {
            let (stream, addr) = listener.accept().await.unwrap();
            stream
                .try_write(&[b'a', b's', b'd', b'f'])
                .expect("couldn't write output");
            panic!("somebody connected: {:?}", addr);
        }
    });

    let cmd = tokio::process::Command::new("/usr/bin/nc")
        .args(["127.1.2.3", "8080"])
        .output()
        .await
        .expect("unexpected execution failure");

    assert!(!cmd.status.success(), "process should fail");

    let _ = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("timeout elapsed");
}

#[ignore = "known failure #58"]
#[tokio::test]
async fn test_socket_connect_deny_one() {
    let nc2 = PathBuf::from("/usr/bin/nc2");
    tokio::fs::copy("/usr/bin/nc", &nc2)
        .await
        .expect("failed to make nc copy");

    let metadata = nc2.metadata().unwrap();
    let inode = metadata.ino();
    println!("nc2 inode: {}", inode);

    let (tx, rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let mut mgr: PolicyManager = PolicyManager::with_default_path().unwrap();

        let mut socket_connect = mgr.attach_socket_connect().unwrap();

        let mut rx = socket_connect.alerts().await.unwrap();

        println!("registering deny policy");
        socket_connect
            .add_policy(SocketConnect {
                subject: PolicySubject::Binary("/usr/bin/nc2".into()),
                allow: Addresses::All,
                deny: Addresses::Addresses(vec![IpAddr::from([127, 1, 2, 4])]),
            })
            .await
            .unwrap();

        tx.send(()).unwrap();
        println!("listening for alarms");

        while let Some(msg) = rx.recv().await {
            // TODO(tjonak): shouldn't PolicySubject::Binary hold a path not an inode?
            if msg.subject != PolicySubject::Binary(format!("{}", inode).into()) {
                panic!("unexpected binary: {:?}", msg);
            }
            println!("alert found: {:?}", msg);
            if msg.addr == IpAddr::from([127, 1, 2, 4]) {
                break;
            }
        }
    });

    let _ = rx.await;

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.1.2.4:8080").await.unwrap();
        println!("listener started");

        loop {
            let (_, addr) = listener.accept().await.unwrap();
            println!("somebody connected: {:?}", addr);
        }
    });

    let cmd = tokio::process::Command::new("/usr/bin/nc")
        .args(["-Nd", "127.1.2.4", "8080"])
        .output()
        .await
        .expect("unexpected execution failure");

    assert!(cmd.status.success(), "different binary should pass");

    let cmd = tokio::process::Command::new(nc2)
        .args(["-Nd", "127.1.2.4", "8080"])
        .output()
        .await
        .expect("unexpected execution failure");

    assert!(!cmd.status.success(), "quarantined binary should fail");

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("timeout elapsed")
        .expect("task panicked");
}
