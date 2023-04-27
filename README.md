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

## Prerequisites

### kernel capabilities

First, you need to have a Linux kernel:
* with BTF support
* with BPF LSM support (kernels >= 5.7)

You can check if your kernel has BTF support by checking whether file
`/sys/kernel/btf/vmlinux` exists. You can also check the kernel configuration:

```bash
$ zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
CONFIG_DEBUG_INFO_BTF=y
```

Next, you need to check if your kernel has BPF LSM support:

```bash
$ cat /sys/kernel/security/lsm
lockdown,capability,selinux,bpf
```

If the output doesn't contain `bpf`, you need to enable BPF LSM by adding
`lsm=[...],bpf` to your kernel config parameters. That can be achieved by
executing the [enable-bpf-lsm.py](https://github.com/deepfence/ebpfguard/blob/main/enable-bpf-lsm.py.py) script.

This script will print modified contents of `/etc/default/grub` file to stdout.
Either pipe it back directly to `/etc/default/grub` or save it somewhere 
and compare contents before swapping to a new version.

Whole command with direct pipe:

```bash
$ ./enable-bpf.lsm.py | sudo tee /etc/default/grub 1>/dev/null
```

This file is used by grub2 to assemble final `grub.cfg`. To trigger reconfiguration
use grub's mkconfig command with `-o <path to grub.cfg>` switch.

Both command name and path to `grub.cfg` are distribution dependent.

On ubuntu:

```
$ sudo grub-mkconfig -o /boot/grub/grub.cfg
```

On fedora:

```
$ sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

After that's done reboot your system.

### rust toolchain and packages

You need the Rust stable and nightly toolchains installed on your system, bpf-linker and bpftool binary.

Install nightly toolchain:

```
$ rustup toolchain install nightly --component rust-src
```

Optionally add miri:

```
$ rustup component add miri --toolchain nightly
```

Finally install bpf-linker:

```
$ cargo install bpf-linker
```

This bpf-linker installation method works on linux x86_64 systems.
For others refer to [aya-rs documentation](https://aya-rs.dev/book/start/development/).

To install bpftool either use distro provided package or build it from [source](https://github.com/libbpf/bpftool).

On ubuntu it is a part of linux-tools:

```
$ sudo apt install linux-tools-$(uname -r)
```

## Development

All commands should be executed from repository/workspace root folder unless noted otherwise.

### Compilation

First compile ebpf bytecode with the following command. It will be embedded
in userspace binary using aya.

```
$ cargo xtask build-ebpf
```

Then userspace code.

```
$ cargo build
```

### Tests

Commands in this subsection mirror state of CI pipeline.

Regular tests

```
$ cargo test
```

Formatting gateway. Drop check subflag to autoformat.

```
$ cargo fmt --all -- --check
```

Clippy lints.

```
$ cargo clippy --workspace -- --deny warnings
```

Miri verification.

```
$ cargo +nightly miri test --all-targets
```

Note that miri verification requires nightly toolchain as well as miri component. To add them execute:

```
$ rustup toolchain install nightly --component rust-src
$ rustup component add miri --toolchain nightly
```

## LSM hooks

LSM hooks supported by Ebpfguard are:

* [`bprm_check_security`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L62)
* [`file_open`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L620)
* [`sb_mount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L128)
* [`sb_remount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L147)
* [`sb_umount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L159)
* [`socket_bind`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L904)
* [`socket_connect`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L912)
* [`task_fix_setuid`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L709)

## Examples

For usage examples check [EXAMPLES.md](EXAMPLES.md).

## Get in touch

Thank you for using Ebpfguard. Please feel welcome to participate in the [Deepfence community](COMMUNITY.md).

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
