use aya_bpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};
use ebpfguard_common::{alerts, policy};

#[map]
pub static ALERT_BPRM_CHECK_SECURITY: PerfEventArray<alerts::BprmCheckSecurity> =
    PerfEventArray::pinned(1024, 0);

/// Map of allowed file open paths for each binary.
#[map]
pub static ALLOWED_FILE_OPEN: HashMap<u64, policy::Paths> = HashMap::pinned(1024, 0);

/// Map of denied file open paths for each binary.
#[map]
pub static DENIED_FILE_OPEN: HashMap<u64, policy::Paths> = HashMap::pinned(1024, 0);

/// Map of alerts for `file_open` LSM hook inspection.
#[map]
pub static ALERT_FILE_OPEN: PerfEventArray<alerts::FileOpen> = PerfEventArray::pinned(1024, 0);

/// Map indicating which binaries are allowed to use `setuid`.
#[map]
pub static ALLOWED_TASK_FIX_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

/// Map indicating which binaries are denied to use `setuid`.
#[map]
pub static DENIED_TASK_FIX_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

/// Map of alerts for `setuid` LSM hook inspection.
#[map]
pub static ALERT_TASK_FIX_SETUID: PerfEventArray<alerts::TaskFixSetuid> =
    PerfEventArray::pinned(1024, 0);

// Map indicating which binaries are allowed to mount filesystems.
#[map]
pub static ALLOWED_SB_MOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map indicating which binaries are denied to mount filesystems.
#[map]
pub static DENIED_SB_MOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map of alerts for `sb_mount` LSM hook inspection.
#[map]
pub static ALERT_SB_MOUNT: PerfEventArray<alerts::SbMount> = PerfEventArray::pinned(1024, 0);

// Map indicating which binaries are allowed to remount filesystems.
#[map]
pub static ALLOWED_SB_REMOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map indicating which binaries are denied to remount filesystems.
#[map]
pub static DENIED_SB_REMOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map of alerts for `sb_remount` LSM hook inspection.
#[map]
pub static ALERT_SB_REMOUNT: PerfEventArray<alerts::SbRemount> = PerfEventArray::pinned(1024, 0);

// Map indicating which binaries are allowed to unmount filesystems.
#[map]
pub static ALLOWED_SB_UMOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map indicating which binaries are denied to unmount filesystems.
#[map]
pub static DENIED_SB_UMOUNT: HashMap<u64, u8> = HashMap::pinned(1024, 0);

// Map of alerts for `sb_umount` LSM hook inspection.
#[map]
pub static ALERT_SB_UMOUNT: PerfEventArray<alerts::SbUmount> = PerfEventArray::pinned(1024, 0);

/// Map of allowed socket bind ports for each binary.
#[map]
pub static ALLOWED_SOCKET_BIND: HashMap<u64, policy::Ports> = HashMap::pinned(1024, 0);

/// Map of denied socket bind ports for each binary.
#[map]
pub static DENIED_SOCKET_BIND: HashMap<u64, policy::Ports> = HashMap::pinned(1024, 0);

/// Map of alerts for `socket_bind` LSM hook inspection.
#[map]
pub static ALERT_SOCKET_BIND: PerfEventArray<alerts::SocketBind> = PerfEventArray::pinned(1024, 0);

/// Map of allowed socket connect IPv4 addresses for each binary.
#[map]
pub static ALLOWED_SOCKET_CONNECT_V4: HashMap<u64, policy::Ipv4Addrs> = HashMap::pinned(1024, 0);

/// Map of denied socket connect IPv4 addresses for each binary.
#[map]
pub static DENIED_SOCKET_CONNECT_V4: HashMap<u64, policy::Ipv4Addrs> = HashMap::pinned(1024, 0);

/// Map of allowed socket connect IPv6 addresses for each binary.
#[map]
pub static ALLOWED_SOCKET_CONNECT_V6: HashMap<u64, policy::Ipv6Addrs> = HashMap::pinned(1024, 0);

/// Map of denied socket connect IPv6 addresses for each binary.
#[map]
pub static DENIED_SOCKET_CONNECT_V6: HashMap<u64, policy::Ipv6Addrs> = HashMap::pinned(1024, 0);

/// Map of alerts for `socket_connect` LSM hook inspection.
#[map]
pub static ALERT_SOCKET_CONNECT: PerfEventArray<alerts::SocketConnect> =
    PerfEventArray::pinned(1024, 0);
