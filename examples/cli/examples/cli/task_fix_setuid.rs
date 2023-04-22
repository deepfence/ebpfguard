use cli_table::{Cell, Style, Table, TableStruct};
use guardity::PolicyManager;

pub(crate) async fn list_task_fix_setuid(
    policy_manager: &mut PolicyManager,
) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let task_fix_setuid = policy_manager.manage_task_fix_setuid()?;

    for policy in task_fix_setuid.list_policies().await? {
        table.push(vec![policy.subject.to_string(), policy.allow.to_string()]);
    }

    let table = table.table().title(vec![
        "action".cell().bold(true),
        "subject".cell().bold(true),
    ]);

    Ok(table)
}
