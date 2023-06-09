use std::{fs, path::Path};

use crate::error::EbpfguardError;

use super::Policy;

pub fn read_policies<P: AsRef<Path>>(path: P) -> Result<Vec<Policy>, EbpfguardError> {
    let path = path.as_ref();
    let yaml = fs::read_to_string(path)?;
    let policies = serde_yaml::from_str::<Vec<Policy>>(&yaml)?;
    Ok(policies)
}
