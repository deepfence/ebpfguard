use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::fs;

pub mod engine;
pub mod reader;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicySubject {
    #[serde(rename = "process")]
    Process(PathBuf),
    #[serde(rename = "container")]
    Container(String),
    #[serde(rename = "all")]
    All,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Paths {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "paths")]
    Paths(Vec<PathBuf>),
}

// NOTE(vadorovsky): Converting from `guardity_common::Paths` to `Paths`
// requires resolving inodes to paths. Inode/path resolution is not a
// symmetrical operation (path -> inode resolution is a simple file metadata
// lookup, while inode -> path resolution requires more complex per-filesystem
// operations). Therefore, `Into` and `From` traits have to be implemented
// separately.
#[allow(clippy::from_over_into)]
impl Into<guardity_common::Paths> for Paths {
    fn into(self) -> guardity_common::Paths {
        match self {
            Paths::All => guardity_common::Paths {
                paths: [0; guardity_common::MAX_PATHS],
                len: 0,
                all: true,
                _padding: [0; 7],
            },
            Paths::Paths(paths) => {
                let mut ebpf_paths = [0; guardity_common::MAX_PATHS];
                for (i, path) in paths.iter().enumerate() {
                    ebpf_paths[i] = fs::inode(path).unwrap();
                }
                guardity_common::Paths {
                    paths: ebpf_paths,
                    len: paths.len(),
                    all: false,
                    _padding: [0; 7],
                }
            }
        }
    }
}

impl From<guardity_common::Paths> for Paths {
    fn from(paths: guardity_common::Paths) -> Self {
        if paths.all {
            Paths::All
        } else {
            Paths::Paths(
                paths.paths[..paths.len]
                    .iter()
                    // TODO(vadorovsky): Resolve inodes to paths properly.
                    .map(|p| PathBuf::from(p.to_string()))
                    .collect::<Vec<_>>(),
            )
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
impl Into<guardity_common::Ports> for Ports {
    fn into(self) -> guardity_common::Ports {
        match self {
            Ports::All => guardity_common::Ports::new(true, 0, [0; guardity_common::MAX_PORTS]),
            Ports::Ports(ports) => {
                let mut ebpf_ports = [0; guardity_common::MAX_PORTS];
                for (i, port) in ports.iter().enumerate() {
                    ebpf_ports[i] = *port;
                }
                guardity_common::Ports::new(false, ports.len(), ebpf_ports)
            }
        }
    }
}

impl From<guardity_common::Ports> for Ports {
    fn from(ports: guardity_common::Ports) -> Self {
        if ports.all {
            Ports::All
        } else {
            Ports::Ports(ports.ports[..ports.len].to_vec())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    #[serde(rename = "file_open")]
    FileOpen {
        subject: PolicySubject,
        allow: Paths,
        deny: Paths,
    },
    #[serde(rename = "setuid")]
    SetUid { subject: PolicySubject, allow: bool },
    #[serde(rename = "socket_bind")]
    SocketBind {
        subject: PolicySubject,
        allow: Ports,
        deny: Ports,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file_open() {
        let yaml = "
- !file_open
  subject: all
  allow: all
  deny: !paths
    - /root/s3cr3tdir
- !file_open
  subject: !process /usr/bin/myapp
  allow: !paths
    - /etc/myapp
  deny: all
- !file_open
  subject: !container docker.io/myapp
  allow: !paths
    - /etc/myapp
  deny: all
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 3);
        assert_eq!(
            policy[0],
            Policy::FileOpen {
                subject: PolicySubject::All,
                allow: Paths::All,
                deny: Paths::Paths(vec![PathBuf::from("/root/s3cr3tdir")])
            }
        );
        assert_eq!(
            policy[1],
            Policy::FileOpen {
                subject: PolicySubject::Process(PathBuf::from("/usr/bin/myapp")),
                allow: Paths::Paths(vec![PathBuf::from("/etc/myapp")]),
                deny: Paths::All
            }
        );
        assert_eq!(
            policy[2],
            Policy::FileOpen {
                subject: PolicySubject::Container("docker.io/myapp".to_string()),
                allow: Paths::Paths(vec![PathBuf::from("/etc/myapp")]),
                deny: Paths::All
            }
        );
    }

    #[test]
    fn test_setuid() {
        let yaml = "
- !setuid
  subject: all  
  allow: false
- !setuid
  subject: !process /usr/bin/sudo
  allow: true
- !setuid
  subject: !container deepfenceio/deepfence_agent_ce
  allow: true
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 3);
        assert_eq!(
            policy[0],
            Policy::SetUid {
                subject: PolicySubject::All,
                allow: false
            }
        );
        assert_eq!(
            policy[1],
            Policy::SetUid {
                subject: PolicySubject::Process(PathBuf::from("/usr/bin/sudo")),
                allow: true
            }
        );
        assert_eq!(
            policy[2],
            Policy::SetUid {
                subject: PolicySubject::Container("deepfenceio/deepfence_agent_ce".to_string()),
                allow: true
            }
        );
    }

    #[test]
    fn test_socket_bind() {
        let yaml = "
- !socket_bind
  subject: !process /usr/bin/nginx
  allow: !ports
    - 80
    - 443
  deny: all
- !socket_bind
  subject: !process /usr/bin/python
  allow: !ports
    - 8080
  deny: all
- !socket_bind
  subject: !container docker.io/nginx
  allow: !ports
    - 80
    - 443
  deny: all
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 3);
        assert_eq!(
            policy[0],
            Policy::SocketBind {
                subject: PolicySubject::Process(PathBuf::from("/usr/bin/nginx")),
                allow: Ports::Ports(vec![80, 443]),
                deny: Ports::All
            }
        );
        assert_eq!(
            policy[1],
            Policy::SocketBind {
                subject: PolicySubject::Process(PathBuf::from("/usr/bin/python")),
                allow: Ports::Ports(vec![8080]),
                deny: Ports::All
            }
        );
        assert_eq!(
            policy[2],
            Policy::SocketBind {
                subject: PolicySubject::Container("docker.io/nginx".to_string()),
                allow: Ports::Ports(vec![80, 443]),
                deny: Ports::All
            }
        )
    }
}
