# Development

This section assumes that you previously fulfilled [prerequisites](prerequisites.md).

All commands should be executed from repository/workspace root folder unless noted otherwise.

## Compilation

First compile ebpf bytecode with the following command. It will be embedded
in userspace binary using aya.

```
$ cargo xtask build-ebpf
```

Then userspace code.

```
$ cargo build
```

## Tests

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

Miri verification. Requires optional dependencies from [miri section](prerequisites.md#miri)

```
$ cargo +nightly miri test --all-targets
```
