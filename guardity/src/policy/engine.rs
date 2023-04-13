use aya::{maps::HashMap, Bpf};
use guardity_common::Paths;
use log::info;

use super::{Policy, PolicySubject};
use crate::fs;

pub const INODE_WILDCARD: u64 = 0;

pub fn process_policy(bpf: &mut Bpf, policy: Policy) -> anyhow::Result<()> {
    info!("Processing policy: {:?}", policy);
    match policy {
        Policy::FileOpen {
            subject,
            allow,
            deny,
        } => {
            let allow: Paths = allow.into();
            let deny: Paths = deny.into();
            match subject {
                PolicySubject::Process(path) => {
                    let bin_inode = fs::inode(path)?;

                    let mut allowed_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("ALLOWED_FILE_OPEN").unwrap().try_into()?;
                    allowed_file_open.insert(bin_inode, allow, 0)?;

                    let mut denied_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("DENIED_FILE_OPEN").unwrap().try_into()?;
                    denied_file_open.insert(bin_inode, deny, 0)?;
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    let mut allowed_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("ALLOWED_FILE_OPEN").unwrap().try_into()?;
                    allowed_file_open.insert(INODE_WILDCARD, allow, 0)?;

                    let mut denied_file_open: HashMap<_, u64, Paths> =
                        bpf.map_mut("DENIED_FILE_OPEN").unwrap().try_into()?;
                    denied_file_open.insert(INODE_WILDCARD, deny, 0)?;
                }
            }
        }
        Policy::SetUid { subject, allow } => {
            match subject {
                PolicySubject::Process(path) => {
                    let inode = fs::inode(path)?;
                    if allow {
                        let mut allowed_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;
                        allowed_setuid.insert(inode, 0, 0)?;
                    } else {
                        let mut denied_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("DENIED_SETUID").unwrap().try_into()?;
                        denied_setuid.insert(inode, 0, 0)?;
                    }
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    if allow {
                        let mut allowed_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;
                        allowed_setuid.insert(INODE_WILDCARD, 0, 0)?;
                    } else {
                        let mut denied_setuid: HashMap<_, u64, u8> =
                            bpf.map_mut("DENIED_SETUID").unwrap().try_into()?;
                        denied_setuid.insert(INODE_WILDCARD, 0, 0)?;
                    }
                }
            };
        }
    }
    Ok(())
}
