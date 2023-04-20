use std::path::PathBuf;

use aya::Bpf;
use cli_table::{print_stdout, Cell, Style, Table};
use guardity::policy::{engine, reader};

use self::{
    file_open::list_file_open, setuid::list_setuid, socket_bind::list_socket_bind,
    socket_connect::list_socket_connect,
};

pub(crate) mod file_open;
pub(crate) mod setuid;
pub(crate) mod socket_bind;
pub(crate) mod socket_connect;

pub(crate) fn add_policies(bpf: &mut Bpf, r#path: PathBuf) -> anyhow::Result<()> {
    let policies = reader::read_policies(r#path)?;
    for policy in policies {
        engine::process_policy(bpf, policy)?;
    }
    Ok(())
}

pub(crate) fn list_policies(bpf: &mut Bpf) -> anyhow::Result<()> {
    let file_open = list_file_open(bpf)?;
    let setuid = list_setuid(bpf)?;
    let socket_bind = list_socket_bind(bpf)?;
    let socket_connect = list_socket_connect(bpf)?;

    let table = vec![
        vec!["file_open".cell()],
        vec![file_open.display()?.cell()],
        vec!["setuid".cell()],
        vec![setuid.display()?.cell()],
        vec!["socket_bind".cell()],
        vec![socket_bind.display()?.cell()],
        vec!["socket_connect".cell()],
        vec![socket_connect.display()?.cell()],
    ]
    .table()
    .title(vec!["Policy".cell().bold(true)]);

    print_stdout(table)?;

    Ok(())
}
