![Deepfence Logo](images/readme/deepfence-logo.png)

[![GitHub license](https://img.shields.io/github/license/deepfence/ebpfguard)](https://github.com/deepfence/ebpfguard/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/ebpfguard)](https://github.com/deepfence/ebpfguard/stargazers)
[![Workflow Status](https://github.com/deepfence/ebpfguard/workflows/build-test/badge.svg)](https://github.com/deepfence/ebpfguard/actions?query=workflow)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/ebpfguard)](https://github.com/deepfence/ebpfguard/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)
<h3 align="center">
<a
    href="https://runacap.com/ross-index/annual-2022/"
    target="_blank"
    rel="noopener"
>
    <img
        style="width: 260px; height: 56px"
        src="https://runacap.com/wp-content/uploads/2023/02/Annual_ROSS_badge_black_2022.svg"
        alt="ROSS Index - Fastest Growing Open-Source Startups | Runa Capital"
        width="260"
        height="56"
    />
</a>
</h3>

# Ebpfguard

**Ebpfguard** is a library for managing Linux security policies. It is based on
[LSM hooks](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html),
but without necessity to write any kernel modules or eBPF programs directly.
It allows to write policies in Rust (or YAML) in user space.

It's based on eBPF and [Aya](https://aya-rs.dev) library, but takes away
the need to use them directly.

## Usage example

Deny mount operation for all users.

```rust
    const BPF_MAPS_PATH: &str = "/sys/fs/bpf/example_sb_mount";

    // Create a directory where ebpfguard policy manager can store its BPF
    // objects (maps).
    std::fs::create_dir_all(BPF_MAPS_PATH)?;

    // Create a policy manager.
    let mut policy_manager = PolicyManager::new(BPF_MAPS_PATH)?;

    // Attach the policy manager to the mount LSM hook.
    let mut sb_mount = policy_manager.attach_sb_mount()?;

    // Get the receiver end of the alerts channel (for the `file_open` LSM
    // hook).
    let mut sb_mount_rx = sb_mount.alerts().await?;

    // Define policies which deny mount operations for all processes (except
    // for the specified subject, if defined).
    sb_mount
        .add_policy(SbMount {
            subject: PolicySubject::All,
            allow: false,
        })
        .await?;

    if let Some(alert) = sb_mount_rx.recv().await {
        info!(
            "sb_mount alert: pid={} subject={}",
            alert.pid, alert.subject
        );
    }
```

Imports and cargo file are available in [example source code](examples/readme_mount). For more examples check out [EXAMPLES.md](doc/EXAMPLES.md).


## Supported LSM hooks

LSM hooks supported by Ebpfguard are:

* [`bprm_check_security`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L62)
* [`file_open`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L620)
* [`sb_mount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L128)
* [`sb_remount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L147)
* [`sb_umount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L159)
* [`socket_bind`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L904)
* [`socket_connect`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L912)
* [`task_fix_setuid`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L709)

## Prerequisites

Check [PREREQUISISTES.md](doc/PREREQUISISTES.md) to set up your environment.

## Development

Check [Development.md](doc/DEVELOPMENT.md) for compillation and testing commands.

## Get in touch

Thank you for using Ebpfguard. Please feel welcome to participate in the [Deepfence community](doc/COMMUNITY.md).

* [Deepfence Community Website](https://community.deepfence.io) 
* [<img src="https://img.shields.io/badge/slack-@deepfence-brightgreen.svg?logo=slack">](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ) Got a question, need some help?  Find the Deepfence team on Slack
* [![GitHub issues](https://img.shields.io/github/issues/deepfence/ebpfguard)](https://github.com/deepfence/ebpfguard/issues) Got a feature request or found a bug?  Raise an issue
<!-- * [![Documentation](https://img.shields.io/badge/documentation-read-green)](https://community.deepfence.io/docs/ebpfguard/) Read the documentation in the [Deepfence Ebpfguard Documentation](https://community.deepfence.io/docs/ebpfguard/) -->
<!-- * [productsecurity at deepfence dot io](SECURITY.md): Found a security issue? Share it in confidence -->
* Find out more at [deepfence.io](https://deepfence.io/)

## License

Ebpfguard's userspace part is licensed under
[Apache License, version 2.0](https://github.com/deepfence/ebpfguard/blob/main/LICENSE).

eBPF programs inside ebpfguard-ebpf directory are licensed under
[GNU General Public License, version 2](https://github.com/deepfence/ebpfguard/blob/main/ebpfguard-ebpf/LICENSE).
