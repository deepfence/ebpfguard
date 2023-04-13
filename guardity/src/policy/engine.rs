use aya::{maps::HashMap, Bpf};
use log::info;

use super::{Policy, PolicySubject};
use crate::fs;

pub const INODE_WILDCARD: u64 = 0;

pub fn process_policy(bpf: &mut Bpf, policy: Policy) -> anyhow::Result<()> {
    info!("Processing policy: {:?}", policy);
    match policy {
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
