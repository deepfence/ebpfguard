use cli_table::{Cell, Style, Table, TableStruct};
use ebpfguard::{policy::Addresses, PolicyManager};

pub(crate) async fn list_socket_connect(
    policy_manager: &mut PolicyManager,
) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let socket_connect = policy_manager.manage_socket_connect()?;

    for policy in socket_connect.list_policies().await? {
        let allow = match policy.allow {
            Addresses::All => "all".to_owned(),
            Addresses::Addresses(addresses) => addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let deny = match policy.deny {
            Addresses::All => "all".to_owned(),
            Addresses::Addresses(addresses) => addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        table.push(vec![policy.subject.to_string(), allow, deny]);
    }

    let table = table.table().title(vec![
        "Subject".cell().bold(true),
        "Allowed".cell().bold(true),
        "Denied".cell().bold(true),
    ]);
    Ok(table)
}
