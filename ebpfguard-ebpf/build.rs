use std::{
    env,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use aya_tool::generate::InputFile;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("vmlinux.rs");

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
    )
    .unwrap();

    let mut out = File::create(&dest_path).unwrap();
    write!(out, "{}", bindings).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
