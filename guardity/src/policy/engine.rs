use aya::{maps::HashMap, Bpf};

use super::{Policy, PolicySubject};
use crate::fs;

pub const INODE_WILDCARD: u64 = 0;

pub fn process_policy(bpf: &mut Bpf, policy: Policy) -> anyhow::Result<()> {
    match policy {
        Policy::SetUid { subject, allow } => {
            let mut allowed_setuid: HashMap<_, u64, u8> =
                bpf.map_mut("ALLOWED_SETUID").unwrap().try_into()?;
            match subject {
                PolicySubject::Process(path) => {
                    let inode = fs::inode(path)?;
                    if allow {
                        allowed_setuid.insert(&inode, &0, 0)?;
                    } else {
                        allowed_setuid.remove(&inode)?;
                    }
                }
                PolicySubject::Container(_) => {
                    unimplemented!();
                }
                PolicySubject::All => {
                    if allow {
                        allowed_setuid.insert(&INODE_WILDCARD, &0, 0)?;
                    } else {
                        allowed_setuid.remove(&INODE_WILDCARD)?;
                    }
                }
            };
        }
    }
    Ok(())
}
