# Prerequisites

## kernel capabilities

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

## rust toolchain and packages

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
