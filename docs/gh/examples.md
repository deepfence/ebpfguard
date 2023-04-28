# Examples

## Defining single policies

### `file_open`

The [file_open](https://github.com/deepfence/ebpfguard/tree/main/examples/file_open)
example shows how to define a policy for `file_open` LSM hook as Rust code.
It denies the given binary (or all processes, if none defined) from opening
the given directory.

To try it out, let's create a directory and a file inside it:

```bash
$ mkdir /tmp/test
$ echo "foo" > /tmp/test/test
```

Then run our example policy program with:

```bash
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

```bash
[2023-04-22T20:51:01Z INFO  file_open] file_open: pid=3001 subject=980333 path=9632
[2023-04-22T20:51:03Z INFO  file_open] file_open: pid=3010 subject=980298 path=9633
```
#### mount

The [mount](https://github.com/deepfence/ebpfguard/tree/main/examples/file_open)
example shows how to define a policy for `sb_mount`, `sb_remount` and
`sb_umount` LSM hooks as Rust code. It denies the mount operations for all
processes except for the optionally given one.

To try it out, let's create two directories:

```bash
$ mkdir /tmp/test1
$ mkdir /tmp/test2
```

Then run our example policy program, first without providing any binary to
allow mount for (so it's denied for all processes):

```bash
$ RUST_LOG=info cargo xtask run --example mount
```

Let's try to bind mount the first directory to the second one. It should
fail with the following error:

```bash
sudo mount --bind /tmp/test1 /tmp/test2
mount: /tmp/test2: permission denied.
       dmesg(1) may have more information after failed mount system call.
```

And the policy program should show a log like:

```bash
[2023-04-23T21:02:58Z INFO  mount] sb_mount: pid=17363 subject=678150
```

Now let's try to allow mount operations for the mount binary:

```bash
$ RUST_LOG=info cargo xtask run --example mount -- --allow /usr/bin/mount
```

And try to bind mount the first directory to the second one again. It should
succeed this time:

```bash
$ sudo mount --bind /tmp/test1 /tmp/test2
$ mount | grep test
tmpfs on /tmp/test2 type tmpfs (rw,nosuid,nodev,seclabel,nr_inodes=1048576,inode64)
```

### `task_fix_setuid`

The [task_fix_setuid](https://github.com/deepfence/ebpfguard/tree/main/examples/task_fix_setuid)
example shows how to define a policy for `task_fix_setuid` LSM hook as Rust
code. It denies the `setuid` operation for all processes except for the
optionally given one.

To try it out, run our example policy program, first without providing any
binary to allow `setuid` for (so it's denied for all processes):

```bash
$ RUST_LOG=info cargo xtask run --example task_fix_setuid
```

Then try to use `sudo`. It should fail with the following error:

```bash
$ sudo -i
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: error initializing audit plugin sudoers_audit
```

And the policy program should show log like:

```bash
[2023-04-23T15:15:00Z INFO  task_fix_setuid] file_open: pid=25604 subject=674642 old_uid=1000 old_gid=1000 new_uid=0 new_gid=1000
```

Now, let's try to allow `setuid` for a specific binary. Let's use `sudo`:

```bash
$ RUST_LOG=info cargo xtask run --example task_fix_setuid -- --allow /usr/bin/sudo
```

Then try to use `sudo` again. It should work this time:

```bash
$ sudo -i
# whoami
root
```

## Daemon with CLI and YAML engine

Run the daemon with:

```bash
$ RUST_LOG=info cargo xtask run --example daemon
```

Then manage the policies using the CLI:

```bash
$ cargo xtask run --example cli -- --help
```

You can apply policies from the
[example YAML file](https://github.com/deepfence/ebpfguard/blob/main/examples/cli/policy.yaml):

```bash
$ cargo xtask run --example cli -- policy add --path examples/cli/policy.yaml
```
