# PostgreSQL Backup Restore Checker

Your PostgreSQL backup job reports success every night. But have you actually tried restoring the files? `pbrc` restores logical backups into fresh, isolated PostgreSQL containers, checks the recovered database, and writes JSON and Markdown evidence.

It provides evidence about a test restore. It does not guarantee disaster recovery readiness or replace production recovery rehearsals.

## Quickstart

Requirements: stable Rust, Docker with a running daemon, and the selected PostgreSQL image available locally or pullable by Docker.

```sh
cargo install --path .
pbrc doctor
pbrc demo
pbrc check --backup ./backups/app.dump --postgres-major 17
pbrc check --backup ./backups/app.dump --expectations ./expectations.toml --strict --format json
```

`pbrc demo --out ./demo-output` creates real backups using `pg_dump` for all five supported formats. It verifies a healthy backup, rejects a truncated archive, and detects a valid but incomplete backup using expectations. Reports and fixtures are saved in the selected output directory.

## Commands

- `pbrc check --backup PATH`: restore a selected backup into a new container. `--directory DIR --latest --glob 'app-*.dump'` selects the newest matching regular file; ties are resolved by path ordering.
- `pbrc inspect PATH`: identify format, size, modification time and fingerprint without restoring. This means `INSPECTED`, not `RESTORE VERIFIED`.
- `pbrc doctor`: check Docker daemon access, image availability, container execution and a PostgreSQL smoke query. It does not install or pull Docker or images.
- `pbrc demo`: generate real backups and check them.
- `pbrc report show REPORT.json` and `pbrc report summary REPORT.json`: read saved reports without Docker.
- `pbrc cleanup --run-id ID` or `pbrc cleanup --stale`: preview project-owned containers. Add `--yes` to remove them; stale means older than 24 hours.

`check` also accepts `--postgres-image`, `--config`, `--expectations`, `--report-dir`, `--format text|json|markdown`, `--json`, `--ci`, `--strict`, `--timeout`/`--restore-timeout`, `--startup-timeout`, `--check-timeout`, `--jobs`, `--single-transaction`/`--no-single-transaction`, `--memory-limit`, `--cpu-limit`, `--max-backup-bytes`, `--expected-sha256`, `--keep-on-failure`, `--quiet`, `--verbose`, and `--no-color`. `--jobs` above one is available for custom and directory archives and cannot be combined with `--single-transaction`. `--strict` requires application expectations and requires valid indexes and validated constraints.

## Expectations

See [examples/expectations.toml](examples/expectations.toml). A compact manifest can require tables and exact counts:

```toml
tables = ["public.customers", "public.invoices"]

[row_counts]
"public.customers" = 250
"public.invoices" = 730
```

Detailed `[[tables]]` entries support `required`, `min_rows`, `max_rows`, or `exact_rows`. `[verification]` can require valid indexes and validated constraints, list required indexes/constraints/schemas/extensions, and opt into `pg_amcheck`. `[[queries]]` supports one trusted, read-only `SELECT` or `WITH` assertion with integer, boolean, or string comparisons. Query results are not written into reports.

An optional TOML config can set image/version, report directory, timeouts, resource limits, expectations, backup size limit and expected fingerprint. CLI values override config values; remaining values use defaults. See [examples/pbrc.toml](examples/pbrc.toml). Paths are interpreted from the current working directory.

## Formats and isolation

Supported PostgreSQL versions are 16, 17, and 18. Supported logical formats are PostgreSQL custom (`pg_dump -Fc`), tar (`-Ft`), directory (`-Fd`), plain SQL and gzip-compressed plain SQL. Custom, tar, and directory archives are checked with `pg_restore --list` before restore. Archives use `pg_restore`; SQL uses `psql` with `ON_ERROR_STOP`. Input files stream into the restore process; directory archives are copied with `docker cp`. Parallel restore copies custom/directory archives into the container so `pg_restore` can read them by path.

Each run uses a fresh container on Docker's `none` network, with no published ports, no host mounts, no Docker socket mount, and no external restore target. A new database based on `template0` is created for the restore. Containers have configurable memory and CPU limits and are labeled for safe cleanup. SQL assertions run as a restricted local role inside the same container.

## Reports and exit codes

Each run writes `reports/<run-id>/report.json` and `report.md`. Reports record the artifact fingerprint, selected image, server version, restore duration, database inventory, check results, assurance level, error category and cleanup result. Directory fingerprints use `sha256-tree-v1`: sorted normalized relative paths, each path length and file size, then file bytes are fed to SHA-256. This is not the hash of a tar archive.

Assurance levels are `RESTORABLE`, `STRUCTURALLY_VERIFIED`, and `APPLICATION_VERIFIED`; the level reflects checks actually run. Restore duration is a measurement of this test environment, not a production RTO guarantee. Filesystem modification time does not prove backup creation time or RPO.

Exit codes: 0 passed; 1 required restore or verification failed; 2 invalid arguments/configuration; 3 Docker unavailable or container startup failure; 4 missing, unreadable or unsupported input; 5 incomplete run or timeout; 6 internal error.

## Scheduled use

Run the backup job separately, then pass its local artifact to the checker. For example:

```yaml
- uses: actions/download-artifact@v5
  with:
    name: postgres-backup
    path: ./backups
- run: cargo install --path .
- run: pbrc check --directory ./backups --latest --glob 'app-*.dump' --expectations ./expectations.toml --strict --ci --format json
```

The checker does not download from object storage or schedule backups. Use a protected artifact handoff appropriate for your environment.

## Limitations and security

Version 1 handles logical dumps only. It does not support physical base backups, WAL replay, PITR, cloud retrieval, production restore execution, or schedules. Normal `pg_dump` files may omit roles and global objects. Extensions may be absent from the selected image. PostgreSQL version differences can change restore behavior. `pg_amcheck` is optional and checks only supported structures; it is not a complete corruption proof. Exact row counts and assertions can be expensive.

Restoring a malicious dump executes SQL inside the container. Docker is not a perfect sandbox, so use a disposable VM or runner for untrusted backups. `trust` authentication is used only inside a container with no network; never reuse this authentication setup for a network-accessible database. SQL assertions are trusted operator configuration, although they execute in a restricted read-only role.

## Development and CI

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

CI runs Rust checks and real Docker demos against PostgreSQL 16, 17, and 18. Tagged releases build Linux x86_64/ARM64 and macOS Intel/Apple Silicon binaries with checksums. Each release archive includes the binary, README, and MIT license.

MIT licensed. See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSE](LICENSE).
