use thiserror::Error;

#[derive(Debug, Error)]
pub enum EbpfguardError {
    #[error("Failed to load BPF program: {0}")]
    Bpf(#[from] aya::BpfError),

    #[error("Failed to get BTF info from the system: {0}")]
    Btf(#[from] aya::BtfError),

    #[error("Failed to load BPF program: {0}")]
    BpfProgramError(#[from] aya::programs::ProgramError),

    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Map error: {0}")]
    Map(#[from] aya::maps::MapError),

    #[error("Failed to open a perf buffer: {0}")]
    PerfBuffer(#[from] aya::maps::perf::PerfBufferError),

    #[error("Failed to parse policies from YAML: {0}")]
    YAML(#[from] serde_yaml::Error),
}
