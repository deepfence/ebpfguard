use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("guardity-ebpf/src");
    let names: Vec<&str> = vec![
        "cred",
        "sock",
        "sockaddr",
        "sockaddr_in",
        "sockaddr_in6",
        "task_struct",
    ];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("vmlinux.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
