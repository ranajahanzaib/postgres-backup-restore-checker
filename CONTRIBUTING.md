# Contributing

Contributions are welcome. For substantial changes, open an issue first to discuss the behavior and scope.

## Development setup

Install stable Rust and Docker, then clone the repository:

```sh
git clone https://github.com/ranajahanzaib/postgres-backup-restore-checker.git
cd postgres-backup-restore-checker
cargo build
```

Run the local checks before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

The Docker integration workflow runs `pbrc doctor` and `pbrc demo` against PostgreSQL 16, 17, and 18. Run `cargo run -- demo` locally when Docker is available.

## Pull requests

- Describe the user-visible change and any compatibility impact.
- Add or update tests for changed behavior.
- Update the README or examples when command behavior or configuration changes.
- Do not include database backups, credentials, access tokens, or other private data in issues or pull requests.
- Keep changes focused and use the existing Rust formatting and lint rules.

For security vulnerabilities, follow the process in [SECURITY.md](.github/SECURITY.md) instead of opening a public issue.
