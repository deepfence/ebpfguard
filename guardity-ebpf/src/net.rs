use core::{cmp, mem};

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    cty::c_long,
    maps::HashMap,
    programs::TcContext,
    BpfContext,
};
use guardity_common::{Ipv4Addrs, NetTuple, NetworkAlert, Ports, MAX_IPV4_ADDRS, MAX_PORTS};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    current_binprm_inode,
    maps::{
        ALERT_NETWORK, ALLOWED_ADDRS_EGRESS, ALLOWED_ADDRS_INGRESS, ALLOWED_PORTS_EGRESS,
        ALLOWED_PORTS_INGRESS, DENIED_ADDRS_EGRESS, DENIED_ADDRS_INGRESS, DENIED_PORTS_EGRESS,
        DENIED_PORTS_INGRESS,
    },
    INODE_WILDCARD,
};

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, c_long> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(-1);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub(crate) fn net_tuple(ctx: &TcContext) -> Result<NetTuple, c_long> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => {}
        _ => return Err(-1),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let dst_addr = u32::from_be(unsafe { *ipv4hdr }.dst_addr);
    let src_addr = u32::from_be(unsafe { *ipv4hdr }.src_addr);

    let (dst_port, src_port) = match unsafe { *ipv4hdr }.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            (
                u16::from_be(unsafe { *tcphdr }.dest) as u32,
                u16::from_be(unsafe { *tcphdr }.source) as u32,
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            (
                u16::from_be(unsafe { *udphdr }.dest) as u32,
                u16::from_be(unsafe { *udphdr }.source) as u32,
            )
        }
        _ => return Err(-1),
    };

    Ok(NetTuple {
        dst_addr,
        src_addr,
        dst_port,
        src_port,
    })
}

pub(crate) fn try_classifier(
    ctx: TcContext,
    allowed_addrs: &HashMap<u64, Ipv4Addrs>,
    denied_addrs: &HashMap<u64, Ipv4Addrs>,
    allowed_ports: &HashMap<u64, Ports>,
    denied_ports: &HashMap<u64, Ports>,
    tuple: NetTuple,
    addr: u32,
    port: u32,
) -> Result<i32, c_long> {
    let binprm_inode = current_binprm_inode();

    if let Some(addrs) = unsafe { allowed_addrs.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { denied_addrs.get(&INODE_WILDCARD) } {
                if addrs.all {
                    ALERT_NETWORK.output(
                        &ctx,
                        &NetworkAlert {
                            binprm_inode,
                            tuple,
                        },
                        0,
                    );
                    return Ok(TC_ACT_SHOT);
                }

                for i in 0..cmp::min(addrs.len, MAX_IPV4_ADDRS) {
                    if addrs.addrs[i] == addr {
                        ALERT_NETWORK.output(
                            &ctx,
                            &NetworkAlert {
                                binprm_inode,
                                tuple,
                            },
                            0,
                        );
                        return Ok(TC_ACT_SHOT);
                    }
                }
            }

            if let Some(addrs) = unsafe { denied_addrs.get(&binprm_inode) } {
                if addrs.all {
                    ALERT_NETWORK.output(
                        &ctx,
                        &NetworkAlert {
                            binprm_inode,
                            tuple,
                        },
                        0,
                    );
                    return Ok(TC_ACT_SHOT);
                }

                for i in 0..cmp::min(addrs.len, MAX_IPV4_ADDRS) {
                    if addrs.addrs[i] == addr {
                        ALERT_NETWORK.output(
                            &ctx,
                            &NetworkAlert {
                                binprm_inode,
                                tuple,
                            },
                            0,
                        );
                        return Ok(TC_ACT_SHOT);
                    }
                }
            }
        }
    }

    if let Some(addrs) = unsafe { denied_addrs.get(&INODE_WILDCARD) } {
        if addrs.all {
            if let Some(addrs) = unsafe { allowed_addrs.get(&INODE_WILDCARD) } {
                if addrs.all {
                    return Ok(TC_ACT_PIPE);
                }

                for i in 0..cmp::min(addrs.len, MAX_IPV4_ADDRS) {
                    if addrs.addrs[i] == addr {
                        return Ok(TC_ACT_PIPE);
                    }
                }
            }

            if let Some(addrs) = unsafe { allowed_addrs.get(&binprm_inode) } {
                if addrs.all {
                    return Ok(TC_ACT_PIPE);
                }

                for i in 0..cmp::min(addrs.len, MAX_IPV4_ADDRS) {
                    if addrs.addrs[i] == addr {
                        return Ok(TC_ACT_PIPE);
                    }
                }
            }

            ALERT_NETWORK.output(
                &ctx,
                &NetworkAlert {
                    binprm_inode,
                    tuple,
                },
                0,
            );
            return Ok(TC_ACT_SHOT);
        }
    }

    // if let Some(ports) = unsafe { allowed_ports.get(&INODE_WILDCARD) } {
    //     if ports.all {
    //         if let Some(ports) = unsafe { denied_ports.get(&INODE_WILDCARD) } {
    //             if ports.all {
    //                 ALERT_NETWORK.output(
    //                     &ctx,
    //                     &NetworkAlert {
    //                         binprm_inode,
    //                         tuple,
    //                     },
    //                     0,
    //                 );
    //                 return Ok(TC_ACT_SHOT);
    //             }

    //             for i in 0..cmp::min(ports.len, MAX_PORTS) {
    //                 if ports.ports[i] == port {
    //                     ALERT_NETWORK.output(
    //                         &ctx,
    //                         &NetworkAlert {
    //                             binprm_inode,
    //                             tuple,
    //                         },
    //                         0,
    //                     );
    //                     return Ok(TC_ACT_SHOT);
    //                 }
    //             }
    //         }

    //         if let Some(ports) = unsafe { denied_ports.get(&binprm_inode) } {
    //             if ports.all {
    //                 ALERT_NETWORK.output(
    //                     &ctx,
    //                     &NetworkAlert {
    //                         binprm_inode,
    //                         tuple,
    //                     },
    //                     0,
    //                 );
    //                 return Ok(TC_ACT_SHOT);
    //             }

    //             for i in 0..cmp::min(ports.len, MAX_PORTS) {
    //                 if ports.ports[i] == port {
    //                     ALERT_NETWORK.output(
    //                         &ctx,
    //                         &NetworkAlert {
    //                             binprm_inode,
    //                             tuple,
    //                         },
    //                         0,
    //                     );
    //                     return Ok(TC_ACT_SHOT);
    //                 }
    //             }
    //         }
    //     }
    // }

    // if let Some(ports) = unsafe { denied_ports.get(&INODE_WILDCARD) } {
    //     if ports.all {
    //         if let Some(ports) = unsafe { allowed_ports.get(&INODE_WILDCARD) } {
    //             if ports.all {
    //                 return Ok(TC_ACT_PIPE);
    //             }

    //             for i in 0..cmp::min(ports.len, MAX_PORTS) {
    //                 if ports.ports[i] == port {
    //                     return Ok(TC_ACT_PIPE);
    //                 }
    //             }
    //         }

    //         if let Some(ports) = unsafe { allowed_ports.get(&binprm_inode) } {
    //             if ports.all {
    //                 return Ok(TC_ACT_PIPE);
    //             }

    //             for i in 0..cmp::min(ports.len, MAX_PORTS) {
    //                 if ports.ports[i] == port {
    //                     return Ok(TC_ACT_PIPE);
    //                 }
    //             }
    //         }

    //         ALERT_NETWORK.output(
    //             &ctx,
    //             &NetworkAlert {
    //                 pid: ctx.pid() as u64,
    //                 binprm_inode,
    //                 tuple,
    //             },
    //             0,
    //         );
    //         return Ok(TC_ACT_SHOT);
    //     }
    // }

    Ok(TC_ACT_PIPE)
}

pub(crate) fn try_classifier_egress(ctx: TcContext) -> Result<i32, c_long> {
    let tuple = net_tuple(&ctx)?;

    try_classifier(
        ctx,
        &ALLOWED_ADDRS_EGRESS,
        &DENIED_ADDRS_EGRESS,
        &ALLOWED_PORTS_EGRESS,
        &DENIED_PORTS_EGRESS,
        tuple,
        tuple.dst_addr,
        tuple.dst_port,
    )
}

pub(crate) fn try_classifier_ingress(ctx: TcContext) -> Result<i32, c_long> {
    let tuple = net_tuple(&ctx)?;

    try_classifier(
        ctx,
        &ALLOWED_ADDRS_INGRESS,
        &DENIED_ADDRS_INGRESS,
        &ALLOWED_PORTS_INGRESS,
        &DENIED_PORTS_INGRESS,
        tuple,
        tuple.src_addr,
        tuple.src_port,
    )
}
