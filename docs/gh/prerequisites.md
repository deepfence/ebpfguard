# Prerequisites

This doc describes characteristics that your system needs to run ebpfguard based applications.

[Kernel capabilites](#kernel-capabilities) section is required both for compilation and execution. Other sections are needed only for development.

For development purposes you can either install dependencies from [tools/packages](#toolspackages) and [rust toolchain](#rust-toolchain) sections or use [docker based development environment](docker_devel_env.md).

## kernel capabilities

Kernel capabilities outlined in this section are required for both execution and development.

First, you need to have a Linux kernel:
* with BTF support
* with BPF LSM support (kernels >= 5.7)

You can check if your kernel has BTF support by checking whether file
`/sys/kernel/btf/vmlinux` exists.

You can also check the kernel configuration. Note that location of this configuration is distribution specific.

SUSE:

```bash
$ zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
CONFIG_DEBUG_INFO_BTF=y
```

Ubuntu:
```bash
$ zgrep CONFIG_DEBUG_INFO_BTF /boot/config-"$(uname -r)"
CONFIG_DEBUG_INFO_BTF=y
```

Next, you need to check if your kernel has BPF LSM support:

```bash
$ cat /sys/kernel/security/lsm
lockdown,capability,selinux,bpf
```

If the output doesn't contain `bpf`, you need to enable BPF LSM by adding
`lsm=[...],bpf` to your kernel config parameters.

Be warned that changes to grub and/or kernel config parameters may result
in kernel panic at startup. It is strongly encouraged to make backups of
all files altered in this section.

Kernel parameter modification can be achieved using [enable-bpf-lsm.py](https://github.com/deepfence/ebpfguard/blob/main/enable-bpf-lsm.py) script.
This script will read contents of `/etc/default/grub`, add lsm section of kernel
parameters with `bpf` option appended to `GRUB_CMDLINE_LINUX_DEFAULT` and print
modified contents to its stdout.

Either pipe it back directly to `/etc/default/grub` or save it as a separate file
and compare contents before swapping to a modified version.

Note that script solution is not bulletproof. If your grub configuration is customized it is encouraged to inspect script contents/output and do changes manually.

Whole command with direct pipe:

```bash
$ sudo cp /etc/default/grub{,.bak} && \
    ./enable-bpf.lsm.py | sudo tee /etc/default/grub 1>/dev/null
```

`/etc/default/grub` file is not used directly by grub2. It is used as a parameter source to assemble final configuration file. Path of a final configuration file as well as command which assembles it are distribution dependent.

On ubuntu:

```bash
$ sudo cp /boot/grub/grub.cfg{,.bak} && sudo grub-mkconfig -o /boot/grub/grub.cfg
```

On fedora:

```bash
$ sudo cp /boot/grub2/grub.cfg{,.bak} && sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

After that's done reboot your system.

### Reverting script based configuration changes

Some platforms have additional requirements when `lsm=bpf` is added to kernel parameters.
This may lead to kernel panic during system boot.

As an example on thinkpad x1 with ubuntu 22.04 addition of bpf lsm capacity results 
in a kernel panic with a message that another lsm capability - `integrity` - has to be enabled.

Reboot once again. Wait until grub menu shows up.

Use up/down arrow keys to select one of entries marked with `(recovery mode)`.
`GRUB_CMDLINE_LINUX_DEFAULT` modifications are not present in recovery entries.
On ubuntu those options are available in subsection `Advanced options for Ubuntu`.

Log into the system.

Revert changes by restoring original files. Assumes backup files were created using sample commands from this section.

On ubuntu the following command may be suitable assuming backup files path
are equal to original ones with `.bak` suffix appended.

```bash
$ sudo mv /boot/grub/grub.cfg.bak /boot/grub/grub.cfg && \
    sudo mv /etc/default/grub.bak /etc/default/grub
```

## tools/packages

The following tools have to be available.
- cc
- bpftool
- libclang

Ways to obtain those tools differ between distributions. Each of them may also be installed from source.

On ubuntu 22.04 the following command installs all required tools.

```bash
$ apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libclang-dev \
    linux-tools-$(uname -r)
```

## rust toolchain

You need the Rust stable and nightly toolchains installed on your system, bpf-linker and bpftool binary.

Install rust from https://rustup.rs. Further commands assume availability of rustup command.

Install bindgen-cli:

```bash
$ cargo install bindgen-cli
```

Install bpf-linker:

```
$ cargo install bpf-linker --git https://github.com/noboruma/bpf-linker
```

bpf-linker installation on architectures other than x86_64 may be more involved. Refer to [aya-rs documentation](https://aya-rs.dev/book/start/development/) for instructions.

### miri

As a part of ebpfguard CI pipeline we test for undefined behaviors using [miri](https://github.com/rust-lang/miri).
To run such tests rust nightly toolchain with miri component is needed.

To install nightly toolchain and miri in it run the following command:

```
$ rustup toolchain install nightly --component rust-src miri
```
