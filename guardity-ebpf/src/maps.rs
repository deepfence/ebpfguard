use aya_bpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};
use guardity_common::{Ipv4Addrs, Ports, SocketBindAlert, SocketConnectAlert};

#[map]
pub(crate) static ALLOWED_SOCKET_BIND: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_SOCKET_BIND: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALERT_SOCKET_BIND: PerfEventArray<SocketBindAlert> =
    PerfEventArray::with_max_entries(1024, 0);

#[map]
pub(crate) static ALLOWED_SOCKET_CONNECT: HashMap<u64, Ipv4Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static DENIED_SOCKET_CONNECT: HashMap<u64, Ipv4Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static ALERT_SOCKET_CONNECT: PerfEventArray<SocketConnectAlert> =
    PerfEventArray::with_max_entries(1024, 0);
