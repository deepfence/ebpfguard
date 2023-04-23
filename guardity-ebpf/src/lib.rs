#![no_std]

pub mod binprm;
pub mod bprm_check_security;
pub mod consts;
pub mod file_open;
pub mod maps;
pub mod task_fix_setuid;
pub mod socket_bind;
pub mod socket_connect;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

pub enum Mode {
    Allowlist,
    Denylist,
}

pub enum Action {
    Allow,
    Deny,
}

impl From<Action> for i32 {
    fn from(action: Action) -> Self {
        match action {
            Action::Allow => 0,
            Action::Deny => -1,
        }
    }
}
