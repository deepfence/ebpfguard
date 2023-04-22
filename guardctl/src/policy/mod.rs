use std::path::PathBuf;

use cli_table::{print_stdout, Cell, Style, Table};
use guardity::{policy::reader, PolicyManager};

use self::{
    file_open::list_file_open, socket_bind::list_socket_bind, socket_connect::list_socket_connect,
    task_fix_setuid::list_task_fix_setuid,
};

pub(crate) mod file_open;
pub(crate) mod socket_bind;
pub(crate) mod socket_connect;
pub(crate) mod task_fix_setuid;

pub(crate) async fn add_policies(
    policy_manager: &mut PolicyManager,
    r#path: PathBuf,
) -> anyhow::Result<()> {
    let mut all = policy_manager.manage_all()?;
    let policies = reader::read_policies(r#path)?;
    for policy in policies {
        all.add_policy(policy).await?;
    }
    Ok(())
}

pub(crate) async fn list_policies(policy_manager: &mut PolicyManager) -> anyhow::Result<()> {
    let file_open = list_file_open(policy_manager).await?;
    let setuid = list_task_fix_setuid(policy_manager).await?;
    let socket_bind = list_socket_bind(policy_manager).await?;
    let socket_connect = list_socket_connect(policy_manager).await?;

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
