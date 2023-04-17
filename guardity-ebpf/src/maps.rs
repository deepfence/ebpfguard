use aya_bpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};
use guardity_common::{Ipv4Addrs, NetworkAlert, Ports};

#[map]
pub(crate) static ALLOWED_ADDRS_EGRESS: HashMap<u64, Ipv4Addrs> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_ADDRS_EGRESS: HashMap<u64, Ipv4Addrs> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALLOWED_PORTS_EGRESS: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_PORTS_EGRESS: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALLOWED_ADDRS_INGRESS: HashMap<u64, Ipv4Addrs> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_ADDRS_INGRESS: HashMap<u64, Ipv4Addrs> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALLOWED_PORTS_INGRESS: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static DENIED_PORTS_INGRESS: HashMap<u64, Ports> = HashMap::pinned(1024, 0);

#[map]
pub(crate) static ALERT_NETWORK: PerfEventArray<NetworkAlert> = PerfEventArray::pinned(1024, 0);
