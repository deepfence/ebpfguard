use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::lsm::LsmLink,
};
use ebpfguard_common::{
    alerts as ebpf_alerts,
    policy::{self as ebpf_policy, IpAddrs},
};
use tokio::sync::mpsc::Receiver;

use crate::{alerts, error::EbpfguardError, policy};

use super::{perf_array_alerts, INODE_SUBJECT_MAP};

pub struct SocketConnect {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map_v4: HashMap<MapData, u64, ebpf_policy::Ipv4Addrs>,
    pub(crate) denied_map_v4: HashMap<MapData, u64, ebpf_policy::Ipv4Addrs>,
    pub(crate) allowed_map_v6: HashMap<MapData, u64, ebpf_policy::Ipv6Addrs>,
    pub(crate) denied_map_v6: HashMap<MapData, u64, ebpf_policy::Ipv6Addrs>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl SocketConnect {
    pub async fn add_policy(
        &mut self,
        policy: policy::SocketConnect,
    ) -> Result<(), EbpfguardError> {
        let bin_inode = {
            let mut map = INODE_SUBJECT_MAP.lock().await;
            map.resolve_path(policy.subject)?
        };

        let (allow_v4, allow_v6) = policy.allow.into_ebpf();
        let (deny_v4, deny_v6) = policy.deny.into_ebpf();

        self.allowed_map_v4.insert(bin_inode, allow_v4, 0)?;
        self.denied_map_v4.insert(bin_inode, deny_v4, 0)?;
        self.allowed_map_v6.insert(bin_inode, allow_v6, 0)?;
        self.denied_map_v6.insert(bin_inode, deny_v6, 0)?;

        Ok(())
    }

    pub async fn list_policies(&self) -> Result<Vec<policy::SocketConnect>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map_v4.iter() {
            let (bin_inode, allow_v4) = res?;
            let deny_v4 = self.denied_map_v4.get(&bin_inode, 0)?;
            let allow_v6 = self.allowed_map_v6.get(&bin_inode, 0)?;
            let deny_v6 = self.denied_map_v6.get(&bin_inode, 0)?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            let allow = if allow_v4.all() && allow_v6.all() {
                policy::Addresses::All
            } else {
                let mut addrs = Vec::new();
                for addr in allow_v4.addrs.iter() {
                    if *addr == 0 {
                        break;
                    }
                    addrs.push(IpAddr::V4(Ipv4Addr::from(addr.to_owned())));
                }
                for addr in allow_v6.addrs.iter() {
                    if *addr == [0u8; 16] {
                        break;
                    }
                    addrs.push(IpAddr::V6(Ipv6Addr::from(addr.to_owned())));
                }
                policy::Addresses::Addresses(addrs)
            };
            let deny = if deny_v4.all() && deny_v6.all() {
                policy::Addresses::All
            } else {
                let mut addrs = Vec::new();
                for addr in deny_v4.addrs.iter() {
                    if *addr == 0 {
                        break;
                    }
                    addrs.push(IpAddr::V4(Ipv4Addr::from(addr.to_owned())));
                }
                for addr in deny_v6.addrs.iter() {
                    if *addr == [0u8; 16] {
                        break;
                    }
                    addrs.push(IpAddr::V6(Ipv6Addr::from(addr.to_owned())));
                }
                policy::Addresses::Addresses(addrs)
            };

            policies.push(policy::SocketConnect {
                subject,
                allow,
                deny,
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::SocketConnect>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::SocketConnect, alerts::SocketConnect>(&mut self.perf_array)
            .await
    }
}
