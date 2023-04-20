use aya::{maps::HashMap, Bpf};
use cli_table::{Cell, Style, Table, TableStruct};
use guardity::policy::engine::INODE_WILDCARD;

pub(crate) fn list_setuid(bpf: &mut Bpf) -> anyhow::Result<TableStruct> {
    let mut table = Vec::new();

    let allowed_setuid: HashMap<_, u64, u8> = bpf.map("ALLOWED_SETUID").unwrap().try_into()?;
    for res in allowed_setuid.iter() {
        let (inode, _) = res?;
        if inode == INODE_WILDCARD {
            table.push(vec!["allow".to_string(), "all".to_string()]);
        } else {
            table.push(vec!["allow".to_string(), inode.to_string()]);
        }
    }

    let denied_setuid: HashMap<_, u64, u8> = bpf.map("DENIED_SETUID").unwrap().try_into()?;
    for res in denied_setuid.iter() {
        let (inode, _) = res?;
        if inode == INODE_WILDCARD {
            table.push(vec!["deny".to_string(), "all".to_string()]);
        } else {
            table.push(vec!["deny".to_string(), inode.to_string()]);
        }
    }

    let table = table.table().title(vec![
        "action".cell().bold(true),
        "subject".cell().bold(true),
    ]);

    Ok(table)
}
