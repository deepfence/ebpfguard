use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuardityError {
    #[error("Failed to find an inode for the given path")]
    Inode(#[from] std::io::Error),
}
