use cli_table::{Cell, Style, Table, TableStruct};
use ebpfguard::PolicyManager;

pub(crate) async fn list_sb_mount(
    policy_manager: &mut PolicyManager,
) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let sb_mount = policy_manager.manage_sb_mount()?;

    for policy in sb_mount.list_policies().await? {
        table.push(vec![policy.subject.to_string(), policy.allow.to_string()]);
    }

    let table = table.table().title(vec![
        "action".cell().bold(true),
        "subject".cell().bold(true),
    ]);

    Ok(table)
}
