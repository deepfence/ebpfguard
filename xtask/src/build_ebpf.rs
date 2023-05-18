use std::{path::PathBuf, process::Command};

use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum EbpfArchitecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for EbpfArchitecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => EbpfArchitecture::BpfEl,
            "bpfeb-unknown-none" => EbpfArchitecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for EbpfArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EbpfArchitecture::BpfEl => "bpfel-unknown-none",
            EbpfArchitecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BuildType {
    Debug,
    Release,
}

impl From<bool> for BuildType {
    fn from(value: bool) -> Self {
        match value {
            true => Self::Release,
            false => Self::Debug,
        }
    }
}

impl std::fmt::Display for BuildType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Release => "release",
            Self::Debug => "debug",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: EbpfArchitecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ebpfguard-ebpf");
    let target = format!("--target={}", opts.target);
    let mut args = vec![
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    let build_type = BuildType::from(opts.release);

    if matches!(build_type, BuildType::Release) {
        args.push("--release")
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());

    let source = format!("target/{}/{}/ebpfguard", opts.target, build_type);
    let destination = format!("ebpfguard-ebpf/ebpfguard.{}.obj", build_type);

    std::fs::copy(source, destination)
        .expect("Couldn't copy compiled eBPFObject to destination path");

    Ok(())
}
