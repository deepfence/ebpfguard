use cli_table::{Cell, Style, Table, TableStruct};
use ebpfguard::{policy::Ports, PolicyManager};

pub(crate) async fn list_socket_bind(
    policy_manager: &mut PolicyManager,
) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let socket_bind = policy_manager.manage_socket_bind()?;

    for policy in socket_bind.list_policies().await? {
        let allow = match policy.allow {
            Ports::All => "all".to_owned(),
            Ports::Ports(ports) => ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let deny = match policy.deny {
            Ports::All => "all".to_owned(),
            Ports::Ports(ports) => ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        };
        table.push(vec![policy.subject.to_string(), allow, deny]);
    }

    let table = table.table().title(vec![
        "subject".cell().bold(true),
        "allowed ports".cell().bold(true),
        "denied ports".cell().bold(true),
    ]);

    Ok(table)
}
