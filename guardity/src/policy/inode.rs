use std::{collections::HashMap, path::PathBuf};

use crate::fs;

use super::PolicySubject;

#[derive(Default)]
pub struct InodeSubjectMap {
    map: HashMap<u64, PathBuf>,
}

impl InodeSubjectMap {
    pub fn resolve_path(&mut self, subject: PolicySubject) -> anyhow::Result<u64> {
        match subject {
            PolicySubject::Binary(path) => {
                let inode = fs::inode(&path)?;
                self.map.insert(inode, path);
                Ok(inode)
            }
            PolicySubject::All => Ok(0),
        }
    }

    pub fn resolve_inode(&self, inode: u64) -> PolicySubject {
        match inode {
            0 => PolicySubject::All,
            _ => self
                .map
                .get(&inode)
                .map(|p| PolicySubject::Binary(p.to_owned()))
                .unwrap_or(PolicySubject::Binary(PathBuf::from(inode.to_string()))),
        }
    }
}
