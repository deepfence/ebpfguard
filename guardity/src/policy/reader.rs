use std::{fs, path::Path};

use super::Policy;

pub fn read_policies<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<Policy>> {
    let path = path.as_ref();
    let yaml = fs::read_to_string(path)?;
    let policies = serde_yaml::from_str::<Vec<Policy>>(&yaml)?;
    Ok(policies)
}
