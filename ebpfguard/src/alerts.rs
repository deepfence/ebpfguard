use ebpfguard_common::alerts;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use crate::policy::PolicySubject;

pub trait Alert {}

#[derive(Debug)]
pub struct BprmCheckSecurity {
    pub pid: u32,
    pub subject: PolicySubject,
}

impl Alert for BprmCheckSecurity {}

impl From<alerts::BprmCheckSecurity> for BprmCheckSecurity {
    fn from(alert: alerts::BprmCheckSecurity) -> Self {
        Self {
            pid: alert.pid,
            subject: PolicySubject::Binary(PathBuf::from(alert.binprm_inode.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct FileOpen {
    pub pid: u32,
    pub subject: PolicySubject,
    pub path: PathBuf,
}

impl Alert for FileOpen {}

impl From<alerts::FileOpen> for FileOpen {
    fn from(alert: alerts::FileOpen) -> Self {
        Self {
            pid: alert.pid,
            subject: PolicySubject::Binary(PathBuf::from(alert.binprm_inode.to_string())),
            path: PathBuf::from(alert.inode.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct TaskFixSetuid {
    pub pid: u32,
    pub subject: PolicySubject,
    pub old_uid: u32,
    pub old_gid: u32,
    pub new_uid: u32,
    pub new_gid: u32,
}

impl Alert for TaskFixSetuid {}

impl From<alerts::TaskFixSetuid> for TaskFixSetuid {
    fn from(alert: alerts::TaskFixSetuid) -> Self {
        Self {
            pid: alert.pid,
            subject: PolicySubject::Binary(PathBuf::from(alert.binprm_inode.to_string())),
            old_uid: alert.old_uid,
            old_gid: alert.old_gid,
            new_uid: alert.new_uid,
            new_gid: alert.new_gid,
        }
    }
}

#[derive(Debug)]
pub struct SocketBind {
    pub pid: u32,
    pub subject: PolicySubject,
    pub port: u16,
}

impl Alert for SocketBind {}

impl From<alerts::SocketBind> for SocketBind {
    fn from(alert: alerts::SocketBind) -> Self {
        Self {
            pid: alert.pid,
            subject: PolicySubject::Binary(PathBuf::from(alert.binprm_inode.to_string())),
            port: alert.port,
        }
    }
}

#[derive(Debug)]
pub struct SocketConnect {
    pub pid: u32,
    pub subject: PolicySubject,
    pub addr: IpAddr,
}

impl Alert for SocketConnect {}

impl From<alerts::SocketConnect> for SocketConnect {
    fn from(alert: alerts::SocketConnect) -> Self {
        let addr = if alert.addr_v4 != 0 {
            IpAddr::V4(Ipv4Addr::from(alert.addr_v4))
        } else {
            IpAddr::V6(Ipv6Addr::from(alert.addr_v6))
        };
        Self {
            pid: alert.pid,
            subject: PolicySubject::Binary(PathBuf::from(alert.binprm_inode.to_string())),
            addr,
        }
    }
}
