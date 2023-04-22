# guardity

**Guardity** is a library for managing Linux security policies. It is based on
[LSM hooks](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html),
but without necessity to write any kernel modules or eBPF programs directly.
It allows to write policies in Rust (or YAML) in user space.

It's based on eBPF and [Aya](https://aya-rs.dev) library, but takes away
the need to use them directly.

## Prerequisites

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
executing the [following script](https://raw.githubusercontent.com/vadorovsky/enable-bpf-lsm/main/enable-bpf-lsm.py).

Then you need the Rust stable and nightly toolchains installed on your system,
as well as bpf-linker. You can install these by following these
[instructions](https://aya-rs.dev/book/start/development/).

## LSM hooks

LSM hooks supported by Guardity are:

* [`bprm_check_security`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L62)
* [`file_open`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L620)
* [`task_fix_setuid`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L709)
* [`socket_bind`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L904)
* [`socket_connect`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L912)

## Examples

### Defining single policies

The [file_open](https://github.com/deepfence/guardity/tree/main/examples/file_open)
example shows how to define a policy for `file_open` LSM hook as Rust code.
It denies the given binary (or all processes, if none defined) from opening
the given directory.

To try it out, let's create a directory and a file inside it:

```bash
$ mkdir /tmp/test
$ echo "foo" > /tmp/test/test
```

Then run our example policy program with:

```rust
$ RUST_LOG=info cargo xtask run --example file_open -- --path-to-deny /tmp/test
```

When trying to access that directory and file, you should see that these
operations are denied:

```bash
$ ls /tmp/test/
ls: cannot open directory '/tmp/test/': Operation not permitted
$ cat /tmp/test/test
cat: /tmp/test/test: Operation not permitted
```

The policy application should show logs like:

```rust
[2023-04-22T20:51:01Z INFO  file_open] file_open: pid=3001 subject=980333 path=9632
[2023-04-22T20:51:03Z INFO  file_open] file_open: pid=3010 subject=980298 path=9633
```

### Daemon with CLI and YAML engine

Run the daemon with:

```bash
$ RUST_LOG=info cargo xtask run --example daemon
```

Then manage the policies using the CLI:

```bash
$ cargo xtask run --example cli -- --help
```

You can apply policies from the
[example YAML file](https://github.com/deepfence/guardity/blob/main/examples/cli/policy.yaml):

```bash
$ cargo xtask run --example cli -- policy add --path examples/cli/policy.yaml
```

## License

Guardity's userspace part is licensed under
[Apache License, version 2.0](https://github.com/deepfence/guardity/blob/main/LICENSE).

eBPF programs inside guardity-ebpf directory are licensed under
[GNU General Public License, version 2](https://github.com/deepfence/guardity/blob/main/guardity-ebpf/LICENSE).
