use aya_bpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};
use guardity_common::{
    AlertSocketConnectV4, AlertSocketConnectV6, Ipv4Addrs, Ipv6Addrs, Ports, SocketBindAlert,
};

#[map]
pub(crate) static ALLOWED_SOCKET_BIND: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_SOCKET_BIND: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALERT_SOCKET_BIND: PerfEventArray<SocketBindAlert> =
    PerfEventArray::with_max_entries(1024, 0);

#[map]
pub(crate) static ALLOWED_SOCKET_CONNECT_V4: HashMap<u64, Ipv4Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static DENIED_SOCKET_CONNECT_V4: HashMap<u64, Ipv4Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static ALERT_SOCKET_CONNECT_V4: PerfEventArray<AlertSocketConnectV4> =
    PerfEventArray::with_max_entries(1024, 0);

#[map]
pub(crate) static ALLOWED_SOCKET_CONNECT_V6: HashMap<u64, Ipv6Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static DENIED_SOCKET_CONNECT_V6: HashMap<u64, Ipv6Addrs> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static ALERT_SOCKET_CONNECT_V6: PerfEventArray<AlertSocketConnectV6> =
    PerfEventArray::with_max_entries(1024, 0);
