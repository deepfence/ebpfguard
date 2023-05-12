# Development

This section assumes that you previously fulfilled [prerequisites](prerequisites.md).

All commands should be executed from repository/workspace root folder unless noted otherwise.

## Compilation

Just utilize cargo infrastructure.

```
$ cargo build
```

If you make changes to any code under `ebpfguard-ebpf` and/or `ebpfguard-common` make sure to rebuild eBPF objects.

```
$ cargo xtask build-ebpf
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

Miri verification.

```
$ cargo +nightly miri test --all-targets
```

## Contributing

Before setting up a PR make sure to run

```
cargo clippy --fix && cargo fmt
```

And verify/commit any resulting changes.
