use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub fn inode<P: AsRef<Path>>(path: P) -> Result<u64, std::io::Error> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)?;
    let inode = metadata.ino();
    Ok(inode)
}
