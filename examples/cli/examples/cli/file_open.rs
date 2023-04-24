use cli_table::{Cell, Style, Table, TableStruct};
use ebpfguard::{policy::Paths, PolicyManager};

pub(crate) async fn list_file_open(
    policy_manager: &mut PolicyManager,
) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let file_open = policy_manager.manage_file_open()?;

    for policy in file_open.list_policies().await? {
        let allow = match policy.allow {
            Paths::All => "all".to_owned(),
            Paths::Paths(paths) => paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let deny = match policy.deny {
            Paths::All => "all".to_owned(),
            Paths::Paths(paths) => paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        table.push(vec![policy.subject.to_string(), allow, deny]);
    }

    let table = table.table().title(vec![
        "subject".cell().bold(true),
        "allowed paths".cell().bold(true),
        "denied paths".cell().bold(true),
    ]);

    Ok(table)
}
