use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
    path::PathBuf,
};

use ebpfguard_common::policy as ebpf_policy;
use serde::{Deserialize, Serialize};

use crate::fs;

pub mod inode;
pub mod reader;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicySubject {
    #[serde(rename = "binary")]
    Binary(PathBuf),
    #[serde(rename = "all")]
    All,
}

impl Display for PolicySubject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicySubject::Binary(path) => write!(f, "{}", path.display()),
            PolicySubject::All => write!(f, "all"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Paths {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "paths")]
    Paths(Vec<PathBuf>),
}

// NOTE(vadorovsky): Converting from `ebpfguard_common::Paths` to `Paths`
// requires resolving inodes to paths. Inode/path resolution is not a
// symmetrical operation (path -> inode resolution is a simple file metadata
// lookup, while inode -> path resolution requires more complex per-filesystem
// operations). Therefore, `Into` and `From` traits have to be implemented
// separately.
#[allow(clippy::from_over_into)]
impl Into<ebpf_policy::Paths> for Paths {
    fn into(self) -> ebpf_policy::Paths {
        match self {
            Paths::All => ebpf_policy::Paths {
                paths: [0; ebpf_policy::MAX_PATHS],
            },
            Paths::Paths(paths) => {
                let mut ebpf_paths = [0; ebpf_policy::MAX_PATHS];
                for (i, path) in paths.iter().enumerate() {
                    ebpf_paths[i] = fs::inode(path).unwrap();
                }
                ebpf_policy::Paths { paths: ebpf_paths }
            }
        }
    }
}

impl From<ebpf_policy::Paths> for Paths {
    fn from(paths: ebpf_policy::Paths) -> Self {
        if paths.paths[0] == 0 {
            Paths::All
        } else {
            let mut paths_vec = Vec::new();
            for inode in paths.paths.iter() {
                if *inode == 0 {
                    break;
                }
                // TODO(vadorovsky): Resolve inodes to paths properly.
                paths_vec.push(PathBuf::from(inode.to_string()));
            }
            Paths::Paths(paths_vec)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ports {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "ports")]
    Ports(Vec<u16>),
}

#[allow(clippy::from_over_into)]
impl Into<ebpf_policy::Ports> for Ports {
    fn into(self) -> ebpf_policy::Ports {
        match self {
            Ports::All => ebpf_policy::Ports::new_all(),
            Ports::Ports(ports) => {
                let mut ebpf_ports = [0; ebpf_policy::MAX_PORTS];
                for (i, port) in ports.iter().enumerate() {
                    ebpf_ports[i] = *port;
                }
                ebpf_policy::Ports::new(ebpf_ports)
            }
        }
    }
}

impl From<ebpf_policy::Ports> for Ports {
    fn from(ports: ebpf_policy::Ports) -> Self {
        if ports.all() {
            Ports::All
        } else {
            let mut ports_vec = Vec::new();
            for port in ports.ports.iter() {
                if *port == 0 {
                    break;
                }
                ports_vec.push(*port);
            }
            Ports::Ports(ports_vec)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Addresses {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "addresses")]
    Addresses(Vec<IpAddr>),
}

impl Addresses {
    pub fn into_ebpf(self) -> (ebpf_policy::Ipv4Addrs, ebpf_policy::Ipv6Addrs) {
        match self {
            Addresses::All => (
                ebpf_policy::Ipv4Addrs::new_all(),
                ebpf_policy::Ipv6Addrs::new_all(),
            ),
            Addresses::Addresses(addrs) => {
                let mut ebpf_addrs_v4 = [0; ebpf_policy::MAX_IPV4ADDRS];
                let mut ebpf_addrs_v6 = [[0u8; 16]; ebpf_policy::MAX_IPV6ADDRS];
                let mut i_v4 = 0;
                let mut i_v6 = 0;
                for addr in addrs.iter() {
                    match addr {
                        IpAddr::V4(ipv4) => {
                            ebpf_addrs_v4[i_v4] = (*ipv4).into();
                            i_v4 += 1;
                        }
                        IpAddr::V6(ipv6) => {
                            ebpf_addrs_v6[i_v6] = ipv6.octets();
                            i_v6 += 1;
                        }
                    }
                }
                (
                    ebpf_policy::Ipv4Addrs::new(ebpf_addrs_v4),
                    ebpf_policy::Ipv6Addrs::new(ebpf_addrs_v6),
                )
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    #[serde(rename = "file_open")]
    FileOpen(FileOpen),
    #[serde(rename = "sb_mount")]
    SbMount(SbMount),
    #[serde(rename = "sb_remount")]
    SbRemount(SbRemount),
    #[serde(rename = "sb_umount")]
    SbUmount(SbUmount),
    #[serde(rename = "socket_bind")]
    SocketBind(SocketBind),
    #[serde(rename = "socket_connect")]
    SocketConnect(SocketConnect),
    #[serde(rename = "task_fix_setuid")]
    TaskFixSetuid(TaskFixSetuid),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpen {
    pub subject: PolicySubject,
    pub allow: Paths,
    pub deny: Paths,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbMount {
    pub subject: PolicySubject,
    pub allow: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbRemount {
    pub subject: PolicySubject,
    pub allow: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbUmount {
    pub subject: PolicySubject,
    pub allow: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketBind {
    pub subject: PolicySubject,
    pub allow: Ports,
    pub deny: Ports,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketConnect {
    pub subject: PolicySubject,
    pub allow: Addresses,
    pub deny: Addresses,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFixSetuid {
    pub subject: PolicySubject,
    pub allow: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_file_open() {
        let yaml = "
- !file_open
  subject: all
  allow: all
  deny: !paths
    - /root/s3cr3tdir
- !file_open
  subject: !binary /usr/bin/myapp
  allow: !paths
    - /etc/myapp
  deny: all
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy[0],
            Policy::FileOpen(FileOpen {
                subject: PolicySubject::All,
                allow: Paths::All,
                deny: Paths::Paths(vec![PathBuf::from("/root/s3cr3tdir")])
            })
        );
        assert_eq!(
            policy[1],
            Policy::FileOpen(FileOpen {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/myapp")),
                allow: Paths::Paths(vec![PathBuf::from("/etc/myapp")]),
                deny: Paths::All
            })
        );
    }

    #[test]
    fn test_sb_mount() {
        let yaml = "
- !sb_mount
  subject: all
  allow: false
- !sb_mount
  subject: !binary /usr/bin/mount
  allow: true
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy[0],
            Policy::SbMount(SbMount {
                subject: PolicySubject::All,
                allow: false
            })
        );
        assert_eq!(
            policy[1],
            Policy::SbMount(SbMount {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/mount")),
                allow: true
            })
        );
    }

    #[test]
    fn test_socket_bind() {
        let yaml = "
- !socket_bind
  subject: !binary /usr/bin/nginx
  allow: !ports
    - 80
    - 443
  deny: all
- !socket_bind
  subject: !binary /usr/bin/python
  allow: !ports
    - 8080
  deny: all
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy[0],
            Policy::SocketBind(SocketBind {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/nginx")),
                allow: Ports::Ports(vec![80, 443]),
                deny: Ports::All
            })
        );
        assert_eq!(
            policy[1],
            Policy::SocketBind(SocketBind {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/python")),
                allow: Ports::Ports(vec![8080]),
                deny: Ports::All
            })
        );
    }

    #[test]
    fn test_socket_connect() {
        let yaml = "
- !socket_connect
  subject: !binary /usr/bin/nginx
  allow: !addresses
    - 10.0.0.1
    - 2001:db8:3333:4444:5555:6666:7777:8888
  deny: all
- !socket_connect
  subject: !binary /usr/bin/tomcat
  allow: all
  deny: !addresses
    - 172.16.0.1
    - 2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy[0],
            Policy::SocketConnect(SocketConnect {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/nginx")),
                allow: Addresses::Addresses(vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0x0db8, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888
                    ))
                ]),
                deny: Addresses::All
            })
        );
        assert_eq!(
            policy[1],
            Policy::SocketConnect(SocketConnect {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/tomcat")),
                allow: Addresses::All,
                deny: Addresses::Addresses(vec![
                    IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0x0db8, 0x3333, 0x4444, 0xCCCC, 0xDDDD, 0xEEEE, 0xFFFF
                    )),
                ]),
            })
        );
    }

    #[test]
    fn test_task_fix_setuid() {
        let yaml = "
- !task_fix_setuid
  subject: all
  allow: false
- !task_fix_setuid
  subject: !binary /usr/bin/sudo
  allow: true
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy[0],
            Policy::TaskFixSetuid(TaskFixSetuid {
                subject: PolicySubject::All,
                allow: false
            })
        );
        assert_eq!(
            policy[1],
            Policy::TaskFixSetuid(TaskFixSetuid {
                subject: PolicySubject::Binary(PathBuf::from("/usr/bin/sudo")),
                allow: true
            })
        );
    }
}
