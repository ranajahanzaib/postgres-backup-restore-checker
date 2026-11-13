use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "pbrc",
    version,
    about = "Restore PostgreSQL backups in isolated Docker containers and verify their contents."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Check(Box<CheckArgs>),
    Inspect {
        backup: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Doctor {
        #[arg(long, default_value = "postgres:17-alpine")]
        postgres_image: String,
    },
    Demo {
        #[arg(long, default_value = "demo-output")]
        out: PathBuf,
        #[arg(long, default_value = "postgres:17-alpine")]
        postgres_image: String,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Cleanup {
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        stale: bool,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Args)]
struct CheckArgs {
    #[arg(long, conflicts_with_all = ["directory", "latest"])]
    backup: Option<PathBuf>,
    #[arg(long, requires = "latest")]
    directory: Option<PathBuf>,
    #[arg(long, requires = "directory", conflicts_with = "backup")]
    latest: bool,
    #[arg(long, requires_all = ["directory", "latest"])]
    glob: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, conflicts_with = "postgres_major")]
    postgres_image: Option<String>,
    #[arg(long)]
    postgres_major: Option<String>,
    #[arg(long)]
    expectations: Option<PathBuf>,
    #[arg(long)]
    report_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    ci: bool,
    #[arg(long)]
    strict: bool,
    #[arg(long, alias = "restore-timeout")]
    timeout: Option<u64>,
    #[arg(long)]
    startup_timeout: Option<u64>,
    #[arg(long)]
    check_timeout: Option<u64>,
    #[arg(long)]
    jobs: Option<usize>,
    #[arg(long)]
    single_transaction: bool,
    #[arg(long, conflicts_with = "single_transaction")]
    no_single_transaction: bool,
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,
    #[arg(long)]
    no_color: bool,
    #[arg(long)]
    expected_sha256: Option<String>,
    #[arg(long)]
    max_backup_bytes: Option<u64>,
    #[arg(long)]
    memory_limit: Option<String>,
    #[arg(long)]
    cpu_limit: Option<f64>,
    #[arg(long)]
    keep_on_failure: bool,
}
#[derive(Subcommand)]
enum ReportCommand {
    Show { path: PathBuf },
    Summary { path: PathBuf },
}
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
}
#[derive(Debug, Serialize, Deserialize)]
struct Artifact {
    path: String,
    format: String,
    size_bytes: u64,
    sha256: String,
    fingerprint_algorithm: String,
    modified: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct CheckResult {
    schema_version: u32,
    run_id: String,
    started_at: String,
    finished_at: String,
    artifact: Artifact,
    postgres_image: String,
    postgres_version: Option<String>,
    status: String,
    assurance_level: String,
    restore_duration_ms: u128,
    container_startup_duration_ms: u128,
    readiness_duration_ms: u128,
    backup_transfer_duration_ms: u128,
    verification_duration_ms: u128,
    total_duration_ms: u128,
    tables: Vec<String>,
    database: Option<DatabaseInventory>,
    checks: Vec<Check>,
    error: Option<String>,
    error_category: Option<String>,
    cleanup_status: String,
    expectations_name: Option<String>,
    expectations_description: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
struct DatabaseInventory {
    schemas: u64,
    schema_names: Vec<String>,
    tables: u64,
    views: u64,
    materialized_views: u64,
    indexes: u64,
    invalid_indexes: u64,
    constraints: u64,
    unvalidated_constraints: u64,
    sequences: u64,
    extensions: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Check {
    name: String,
    status: String,
    expected: Option<String>,
    actual: Option<String>,
    detail: Option<String>,
}

fn detect(p: &Path) -> Result<String> {
    if std::fs::symlink_metadata(p)?.file_type().is_symlink() {
        bail!("symbolic-link backups are not supported; provide the actual file or directory")
    }
    if p.is_dir() {
        if p.join("toc.dat").exists() {
            return Ok("directory".into());
        }
        bail!("directory is not a pg_dump directory archive (missing toc.dat)")
    }
    let mut f = File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let mut b = [0u8; 512];
    let n = f.read(&mut b)?;
    if n == 0 {
        bail!("backup is empty")
    }
    if b.starts_with(b"PGDMP") {
        return Ok("custom".into());
    }
    if b.starts_with(&[0x1f, 0x8b]) {
        return Ok("gzip_sql".into());
    }
    if b.get(257..262) == Some(b"ustar") {
        return Ok("tar".into());
    }
    let mut f = File::open(p)?;
    let mut s = [0u8; 4096];
    let n = f.read(&mut s)?;
    let sample = String::from_utf8_lossy(&s[..n]).to_ascii_lowercase();
    if sample.contains("-- postgresql database dump")
        || sample.contains("create ")
        || sample.contains("set ")
        || sample.contains("copy ")
    {
        return Ok("sql".into());
    }
    if p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
    {
        return Ok("sql".into());
    }
    bail!("unsupported or unrecognized backup format")
}
fn validate_gzip(p: &Path, max_bytes: u64) -> Result<()> {
    let file = File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let mut decoder = MultiGzDecoder::new(file);
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = decoder
            .read(&mut buf)
            .context("invalid or truncated gzip SQL stream")?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("decompressed input size overflow")?;
        if total > max_bytes {
            bail!("decompressed SQL exceeds configured limit of {max_bytes} bytes")
        }
    }
    if total == 0 {
        bail!("gzip backup contains an empty stream")
    }
    Ok(())
}
fn artifact(p: &Path) -> Result<Artifact> {
    let kind = detect(p)?;
    let mut h = Sha256::new();
    let mut n = 0u64;
    if kind == "directory" {
        let mut entries = Vec::new();
        collect_files(p, &mut entries)?;
        entries.sort();
        for entry in entries {
            let relative = entry.strip_prefix(p)?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            let file_size = std::fs::metadata(&entry)?.len();
            h.update((relative.len() as u64).to_be_bytes());
            h.update(relative.as_bytes());
            h.update(file_size.to_be_bytes());
            let mut f = File::open(&entry)?;
            let mut buf = [0; 65536];
            loop {
                let k = f.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                h.update(&buf[..k]);
                n += k as u64;
            }
        }
    } else {
        let mut f = File::open(p)?;
        let mut buf = [0; 65536];
        loop {
            let k = f.read(&mut buf)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            n += k as u64;
        }
    }
    let modified = std::fs::metadata(p)?
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
    Ok(Artifact {
        path: p.display().to_string(),
        format: kind,
        size_bytes: n,
        sha256: hex::encode(h.finalize()),
        fingerprint_algorithm: if p.is_dir() {
            "sha256-tree-v1".into()
        } else {
            "sha256".into()
        },
        modified,
    })
}
fn artifact_for_check(p: &Path) -> (Artifact, Option<String>) {
    match artifact(p) {
        Ok(a) => (a, None),
        Err(error) => {
            let metadata = std::fs::symlink_metadata(p).ok();
            let safe_file = metadata
                .as_ref()
                .is_some_and(|m| m.is_file() && !m.file_type().is_symlink());
            let mut h = Sha256::new();
            let mut size = 0u64;
            if safe_file && let Ok(mut file) = File::open(p) {
                let mut buf = [0u8; 65536];
                loop {
                    match file.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            h.update(&buf[..n]);
                            size += n as u64;
                        }
                    }
                }
            }
            let modified = metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
            (
                Artifact {
                    path: p.display().to_string(),
                    format: "unknown".into(),
                    size_bytes: size,
                    sha256: if safe_file {
                        hex::encode(h.finalize())
                    } else {
                        String::new()
                    },
                    fingerprint_algorithm: if safe_file {
                        "sha256".into()
                    } else {
                        "unavailable".into()
                    },
                    modified,
                },
                Some(format!("{error:#}")),
            )
        }
    }
}
fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            bail!(
                "directory archive contains a symbolic link: {}",
                entry.path().display()
            );
        }
        if ty.is_dir() {
            collect_files(&entry.path(), files)?;
        } else if ty.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}
async fn run(args: &[&str]) -> Result<String> {
    let mut child = Command::new("docker")
        .args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Docker CLI unavailable")?;
    let stdout = child.stdout.take().context("Docker stdout unavailable")?;
    let stderr = child.stderr.take().context("Docker stderr unavailable")?;
    let stdout_task = tokio::spawn(read_capped(stdout, 65536));
    let stderr_task = tokio::spawn(read_capped(stderr, 65536));
    let status = tokio::time::timeout(std::time::Duration::from_secs(120), child.wait())
        .await
        .context("Docker command timed out")??;
    let stdout = stdout_task.await??;
    let stderr = stderr_task.await??;
    if !status.success() {
        bail!(
            "Docker command failed (arguments omitted): {}",
            String::from_utf8_lossy(&stderr).trim()
        )
    }
    Ok(String::from_utf8_lossy(&stdout).trim().into())
}
async fn validate_archive(container: &str, path: &Path, kind: &str) -> Result<()> {
    let mut command = Command::new("docker");
    if kind == "directory" {
        command.args([
            "exec",
            container,
            "pg_restore",
            "--list",
            "-Fd",
            "/tmp/pbrc-archive",
        ]);
    } else {
        command.args(["exec", "-i", container, "pg_restore", "--list"]);
    }
    command
        .kill_on_drop(true)
        .stdin(if kind == "directory" {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("starting PostgreSQL archive preflight")?;
    let stderr = child
        .stderr
        .take()
        .context("archive preflight stderr unavailable")?;
    let stderr_task = tokio::spawn(read_capped(stderr, 65536));
    let writer = if kind == "directory" {
        None
    } else {
        let input = File::open(path)?;
        let mut stdin = child
            .stdin
            .take()
            .context("archive preflight stdin unavailable")?;
        Some(tokio::spawn(async move {
            let mut input = tokio::fs::File::from_std(input);
            tokio::io::copy(&mut input, &mut stdin).await?;
            Ok::<(), anyhow::Error>(())
        }))
    };
    let status = tokio::time::timeout(std::time::Duration::from_secs(120), child.wait())
        .await
        .context("archive preflight timed out")??;
    if let Some(writer) = writer {
        writer.await??;
    }
    let stderr = stderr_task.await??;
    if !status.success() {
        bail!(
            "PostgreSQL archive preflight failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )
    }
    Ok(())
}
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(cap.min(8192));
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        let remaining = cap.saturating_sub(out.len());
        out.extend_from_slice(&buffer[..n.min(remaining)]);
    }
    Ok(out)
}
async fn termination_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => "SIGINT", _ = term.recv() => "SIGTERM" }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "interrupt"
    }
}
async fn wait_postgres(container: &str, seconds: u64) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(seconds), async {
        loop {
            let output = Command::new("docker")
                .kill_on_drop(true)
                .args(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])
                .output()
                .await?;
            if output.status.success() {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    })
    .await
    .context("PostgreSQL startup timed out")??;
    Ok(())
}
async fn create_demo_backup(
    image: &str,
    container: &str,
    path: &Path,
    setup_sql: &str,
    format: &str,
) -> Result<()> {
    run(&[
        "run",
        "-d",
        "--rm",
        "--name",
        container,
        "--network",
        "none",
        "--label",
        "io.pbrc.managed=true",
        "--label",
        &format!("io.pbrc.run={container}"),
        "-e",
        "POSTGRES_HOST_AUTH_METHOD=trust",
        image,
    ])
    .await?;
    let work = async {
        wait_postgres(container, 90).await?;
        run(&[
            "exec",
            container,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-c",
            setup_sql,
        ])
        .await?;
        let mut args = vec!["exec", container, "pg_dump"];
        let directory_source = format == "directory";
        match format {
            "custom" => args.push("-Fc"),
            "tar" => args.push("-Ft"),
            "sql" => args.push("-Fp"),
            "directory" => {
                args.extend(["-Fd", "-f", "/tmp/pbrc-directory"]);
            }
            _ => bail!("unknown demo archive format"),
        }
        args.extend(["-U", "postgres", "-d", "postgres"]);
        let output = if directory_source {
            Stdio::null()
        } else {
            Stdio::from(File::create(path)?)
        };
        let mut child = Command::new("docker")
            .args(args)
            .stdout(output)
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stderr = child.stderr.take().context("pg_dump stderr unavailable")?;
        let stderr_task = tokio::spawn(read_capped(stderr, 65536));
        let status = child.wait().await?;
        let stderr = stderr_task.await??;
        if !status.success() {
            bail!(
                "pg_dump failed: {}",
                String::from_utf8_lossy(&stderr).trim()
            )
        }
        if directory_source {
            run(&[
                "cp",
                &format!("{container}:/tmp/pbrc-directory"),
                &path.display().to_string(),
            ])
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let work = tokio::select! {result=work=>result,signal=termination_signal()=>Err(anyhow::anyhow!("interrupted by {signal}"))};
    let cleanup = run(&["rm", "-f", container]).await;
    work?;
    cleanup?;
    Ok(())
}
async fn check(path: PathBuf, options: CheckOptions) -> Result<CheckResult> {
    let CheckOptions {
        image,
        expectations,
        report_dir,
        timeout,
        keep,
        expected_sha256,
        max_backup_bytes,
        strict,
        memory_limit,
        cpu_limit,
        check_timeout,
        startup_timeout,
        jobs,
        quiet,
        verbose,
        single_transaction,
    } = options;
    let (art, input_error) = artifact_for_check(&path);
    let preflight_error = if let Some(error) = input_error {
        Some(error)
    } else if jobs == 0 || jobs > 32 {
        Some("restore jobs must be between 1 and 32".into())
    } else if jobs > 1 && !matches!(art.format.as_str(), "custom" | "directory") {
        Some("parallel restore jobs are supported only for custom and directory archives".into())
    } else if jobs > 1 && single_transaction {
        Some("single-transaction restore cannot be combined with parallel jobs".into())
    } else if art.size_bytes > max_backup_bytes {
        Some(format!(
            "backup is {} bytes, above the configured limit of {max_backup_bytes}",
            art.size_bytes
        ))
    } else if art.format == "gzip_sql" {
        validate_gzip(&path, max_backup_bytes)
            .err()
            .map(|e| format!("{e:#}"))
    } else if let Some(expected) = expected_sha256.as_deref() {
        if expected.eq_ignore_ascii_case(&art.sha256) {
            None
        } else {
            Some(format!(
                "artifact fingerprint mismatch: expected {expected}, observed {}",
                art.sha256
            ))
        }
    } else {
        None
    };
    let id = Uuid::new_v4().to_string();
    let name = format!("pbrc-{}", &id[..8]);
    let started = chrono::Utc::now();
    let total_start = Instant::now();
    let mut result = CheckResult {
        schema_version: 1,
        run_id: id.clone(),
        started_at: started.to_rfc3339(),
        finished_at: String::new(),
        artifact: art,
        postgres_image: image.clone(),
        postgres_version: None,
        status: "failed".into(),
        assurance_level: "INSPECTED".into(),
        restore_duration_ms: 0,
        container_startup_duration_ms: 0,
        readiness_duration_ms: 0,
        backup_transfer_duration_ms: 0,
        verification_duration_ms: 0,
        total_duration_ms: 0,
        tables: vec![],
        database: None,
        checks: vec![Check {
            name: "input_preflight".into(),
            status: if preflight_error.is_some() {
                "failed"
            } else {
                "passed"
            }
            .into(),
            expected: Some("supported, readable artifact within configured limits".into()),
            actual: Some(
                if preflight_error.is_some() {
                    "rejected"
                } else {
                    "accepted"
                }
                .into(),
            ),
            detail: preflight_error.clone(),
        }],
        error: None,
        error_category: None,
        cleanup_status: "pending".into(),
        expectations_name: None,
        expectations_description: None,
    };
    let container_start = Instant::now();
    let creation = if preflight_error.is_some() {
        Err(anyhow::anyhow!("artifact preflight failed"))
    } else {
        run(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "--network",
            "none",
            "--memory",
            &memory_limit,
            "--cpus",
            &cpu_limit.to_string(),
            "--label",
            "io.pbrc.managed=true",
            "--label",
            &format!("io.pbrc.run={id}"),
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            &image,
        ])
        .await
    };
    result.container_startup_duration_ms = container_start.elapsed().as_millis();
    let mut readiness_duration_ms = 0u128;
    let mut backup_transfer_duration_ms = 0u128;
    let mut restore_duration_ms = 0u128;
    let mut verification_duration_ms = 0u128;
    let mut container_started = false;
    let operation = async {
        if let Some(error) = preflight_error {
            bail!("{error}");
        }
        if verbose && !quiet {
            eprintln!("[PASS] Backup format and fingerprint verified");
        }
        creation?;
        container_started = true;
        if verbose && !quiet {
            eprintln!("[PASS] Isolated PostgreSQL container started (network disabled)");
        }
        let container_ready_start = Instant::now();
        let ready = tokio::time::timeout(std::time::Duration::from_secs(startup_timeout), async {
            loop {
                let o = Command::new("docker")
                    .args(["exec", &name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])
                    .output()
                    .await?;
                if o.status.success() {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await;
        ready.context("PostgreSQL startup timed out")??;
        readiness_duration_ms = container_ready_start.elapsed().as_millis();
        let kind = result.artifact.format.as_str();
        let target = format!("pbrc_{}", &id[..8]);
        run(&[
            "exec",
            &name,
            "createdb",
            "-T",
            "template0",
            "-U",
            "postgres",
            &target,
        ])
        .await?;
        let copy_archive = kind == "directory" || (jobs > 1 && kind == "custom");
        let transfer_start = Instant::now();
        if copy_archive {
            run(&[
                "cp",
                &path.display().to_string(),
                &format!("{name}:/tmp/pbrc-archive"),
            ])
            .await?;
        }
        backup_transfer_duration_ms = transfer_start.elapsed().as_millis();
        if matches!(kind, "custom" | "tar" | "directory") {
            match validate_archive(&name, &path, kind).await {
                Ok(()) => result.checks.push(Check {
                    name: "archive_readability".into(),
                    status: "passed".into(),
                    expected: Some("pg_restore --list succeeds".into()),
                    actual: Some("archive table of contents is readable".into()),
                    detail: None,
                }),
                Err(error) => {
                    let detail = format!("{error:#}");
                    result.checks.push(Check {
                        name: "archive_readability".into(),
                        status: "failed".into(),
                        expected: Some("pg_restore --list succeeds".into()),
                        actual: Some("archive could not be listed".into()),
                        detail: Some(detail.clone()),
                    });
                    return Err(error);
                }
            }
        }
        let restore_start = Instant::now();
        let mut command = Command::new("docker");
        if copy_archive {
            command.args([
                "exec",
                &name,
                "pg_restore",
                "--exit-on-error",
                "--no-owner",
                "--no-acl",
                "-U",
                "postgres",
                "-d",
                &target,
            ]);
            if jobs > 1 {
                command.arg("-j").arg(jobs.to_string());
            }
            if single_transaction {
                command.arg("--single-transaction");
            }
            command
                .arg(if kind == "directory" { "-Fd" } else { "-Fc" })
                .arg("/tmp/pbrc-archive");
        } else if kind == "custom" || kind == "tar" {
            command.args([
                "exec",
                "-i",
                &name,
                "pg_restore",
                "--exit-on-error",
                "--no-owner",
                "--no-acl",
                "-U",
                "postgres",
                "-d",
                &target,
            ]);
            if single_transaction {
                command.arg("--single-transaction");
            }
        } else {
            command.args([
                "exec",
                "-i",
                &name,
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                &target,
            ]);
            if single_transaction {
                command.arg("--single-transaction");
            }
        }
        command
            .kill_on_drop(true)
            .stdin(if copy_archive {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context("starting restore process")?;
        let stderr = child.stderr.take().context("restore stderr unavailable")?;
        let stderr_task = tokio::spawn(async move {
            let mut stderr = stderr;
            let mut output = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = stderr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let remaining = 65536usize.saturating_sub(output.len());
                output.extend_from_slice(&buf[..n.min(remaining)]);
            }
            Ok::<_, std::io::Error>(output)
        });
        let writer = if !copy_archive {
            let mut input = Box::new(File::open(&path)?) as Box<dyn Read + Send>;
            if kind == "gzip_sql" {
                input = Box::new(MultiGzDecoder::new(input));
            }
            let mut stdin = child.stdin.take().context("restore stdin unavailable")?;
            Some(tokio::task::spawn_blocking(move || {
                let transfer_start = Instant::now();
                let mut buf = [0; 65536];
                let mut written = 0u64;
                loop {
                    let n = input.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    written = written
                        .checked_add(n as u64)
                        .context("decompressed input size overflow")?;
                    if written > max_backup_bytes {
                        bail!(
                            "decompressed SQL exceeds configured limit of {max_backup_bytes} bytes"
                        );
                    }
                    tokio_handle_write(&mut stdin, &buf[..n])?;
                }
                Ok::<_, anyhow::Error>(transfer_start.elapsed().as_millis())
            }))
        } else {
            None
        };
        let status = tokio::time::timeout(std::time::Duration::from_secs(timeout), child.wait())
            .await
            .context("restore timed out")??;
        if let Some(writer) = writer {
            backup_transfer_duration_ms = writer.await??;
        }
        let stderr = stderr_task.await??;
        restore_duration_ms = restore_start.elapsed().as_millis();
        if !status.success() {
            bail!(
                "restore command exited with {status}: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }

        let role_setup = format!(
            "DO $pbrc$ DECLARE s text; BEGIN CREATE ROLE pbrc_verify LOGIN; GRANT CONNECT ON DATABASE {} TO pbrc_verify; FOR s IN SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' LOOP EXECUTE format('GRANT USAGE ON SCHEMA %I TO pbrc_verify', s); EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO pbrc_verify', s); END LOOP; END $pbrc$;",
            quote_ident(&target)
        );
        run(&[
            "exec",
            &name,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            &target,
            "-c",
            &role_setup,
        ])
        .await?;
        let verification_start = Instant::now();

        let output = run(&[
            "exec", &name, "psql", "-XAt", "-U", "postgres", "-d", &target, "-c", "SELECT 1",
        ])
        .await?;
        if output.trim() != "1" {
            bail!("restored database connectivity check returned an unexpected result");
        }
        result.checks.push(Check {
            name: "database_connectivity".into(),
            status: "passed".into(),
            expected: Some("1".into()),
            actual: Some(output.trim().into()),
            detail: None,
        });
        result.postgres_version = Some(
            run(&[
                "exec",
                &name,
                "psql",
                "-XAt",
                "-U",
                "postgres",
                "-d",
                &target,
                "-c",
                "SHOW server_version",
            ])
            .await?,
        );
        let inventory=run(&["exec",&name,"psql","-XAt","-U","postgres","-d",&target,"-c","SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1"]).await?;
        result.tables = inventory
            .lines()
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect();
        result.checks.push(Check {
            name: "application_tables".into(),
            status: if result.tables.is_empty() {
                "warning"
            } else {
                "passed"
            }
            .into(),
            expected: None,
            actual: Some(result.tables.len().to_string()),
            detail: None,
        });
        let counts=run(&["exec",&name,"psql","-XAt","-U","postgres","-d",&target,"-c","SELECT (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%') || '|' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%') || '|' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='v' AND n.nspname NOT IN ('pg_catalog','information_schema')) || '|' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='m' AND n.nspname NOT IN ('pg_catalog','information_schema')) || '|' || (SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')) || '|' || (SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (NOT i.indisvalid OR NOT i.indisready) AND n.nspname NOT IN ('pg_catalog','information_schema')) || '|' || (SELECT count(*) FROM pg_constraint WHERE connamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema'))) || '|' || (SELECT count(*) FROM pg_constraint WHERE NOT convalidated AND connamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema'))) || '|' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema')) || '|' || coalesce((SELECT string_agg(extname,',' ORDER BY extname) FROM pg_extension),'')"]).await?;
        let fields: Vec<_> = counts.trim().split('|').collect();
        if fields.len() != 10 {
            bail!("could not parse database catalog summary");
        }
        let number = |i: usize| fields[i].parse::<u64>().context("invalid catalog count");
        let schema_output=run(&["exec",&name,"psql","-XAt","-U","postgres","-d",&target,"-c","SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' ORDER BY 1"]).await?;
        result.database = Some(DatabaseInventory {
            schemas: number(0)?,
            schema_names: schema_output
                .lines()
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect(),
            tables: number(1)?,
            views: number(2)?,
            materialized_views: number(3)?,
            indexes: number(4)?,
            invalid_indexes: number(5)?,
            constraints: number(6)?,
            unvalidated_constraints: number(7)?,
            sequences: number(8)?,
            extensions: if fields[9].is_empty() {
                vec![]
            } else {
                fields[9].split(',').map(str::to_string).collect()
            },
        });
        let mut cfg = expectations.unwrap_or_default();
        result.expectations_name = cfg.metadata.as_ref().map(|m| m.name.clone());
        result.expectations_description = cfg.metadata.as_ref().and_then(|m| m.description.clone());
        if strict {
            cfg.verification.require_nonempty_database = true;
            cfg.verification.require_valid_indexes = true;
            cfg.verification.require_validated_constraints = true;
        }
        let inv = result
            .database
            .as_ref()
            .context("database inventory unavailable")?;
        for (kind, required, available) in [
            (
                "schema",
                &cfg.verification.required_schemas,
                &inv.schema_names,
            ),
            (
                "extension",
                &cfg.verification.required_extensions,
                &inv.extensions,
            ),
        ] {
            if required.len() > 100 {
                bail!("at most 100 required {kind}s may be configured");
            }
            for expected in required {
                let present = available.iter().any(|x| x == expected);
                result.checks.push(Check {
                    name: format!("required_{kind}:{expected}"),
                    status: if present { "passed" } else { "failed" }.into(),
                    expected: Some("available".into()),
                    actual: Some(if present { "available" } else { "missing" }.into()),
                    detail: None,
                });
                if !present {
                    bail!("required PostgreSQL {kind} {expected} is missing");
                }
            }
        }
        let application_assertions_required = !cfg.row_counts.is_empty()
            || cfg.tables.iter().any(|t| {
                matches!(
                    t,
                    TableExpectation::Name(_)
                        | TableExpectation::Detailed(DetailedTableExpectation {
                            required: true,
                            ..
                        })
                )
            })
            || cfg.queries.iter().any(|q| q.required);
        if cfg.verification.require_nonempty_database && result.tables.is_empty() {
            bail!("verification requires a nonempty application database");
        }
        for (table, count) in cfg.row_counts {
            let q = format!(
                "SET statement_timeout='{check_timeout}s'; SELECT count(*) FROM {}",
                quote_qualified(&table)?
            );
            let actual = run(&[
                "exec", &name, "psql", "-XAt", "-U", "postgres", "-d", &target, "-c", &q,
            ])
            .await?;
            let ok = actual.trim() == count.to_string();
            result.checks.push(Check {
                name: format!("row_count:{table}"),
                status: if ok { "passed" } else { "failed" }.into(),
                expected: Some(count.to_string()),
                actual: Some(actual.trim().into()),
                detail: None,
            });
            if !ok {
                bail!(
                    "row count expectation failed for {table}: expected {count}, got {}",
                    actual.trim()
                );
            }
        }
        for table in cfg.tables {
            let (table_name, required, min_rows, max_rows, exact_rows) = match table {
                TableExpectation::Name(name) => (name, true, None, None, None),
                TableExpectation::Detailed(t) => {
                    (t.name, t.required, t.min_rows, t.max_rows, t.exact_rows)
                }
            };
            let present = result
                .tables
                .iter()
                .any(|x| x == &table_name || x.ends_with(&format!(".{table_name}")));
            if !present {
                result.checks.push(Check {
                    name: format!("table:{table_name}"),
                    status: if required { "failed" } else { "skipped" }.into(),
                    expected: Some("present".into()),
                    actual: Some("missing".into()),
                    detail: None,
                });
                if required {
                    bail!("expected table {table_name} is missing")
                };
                continue;
            }
            result.checks.push(Check {
                name: format!("table:{table_name}"),
                status: "passed".into(),
                expected: Some("present".into()),
                actual: Some("present".into()),
                detail: None,
            });
            if min_rows.is_some() || max_rows.is_some() || exact_rows.is_some() {
                let q = format!(
                    "SET statement_timeout='{check_timeout}s'; SELECT count(*) FROM {}",
                    quote_qualified(&table_name)?
                );
                let actual = run(&[
                    "exec", &name, "psql", "-XAt", "-U", "postgres", "-d", &target, "-c", &q,
                ])
                .await?;
                let count: u64 = actual
                    .trim()
                    .parse()
                    .context("invalid count returned from PostgreSQL")?;
                let ok = min_rows.is_none_or(|v| count >= v)
                    && max_rows.is_none_or(|v| count <= v)
                    && exact_rows.is_none_or(|v| count == v);
                result.checks.push(Check {
                    name: format!("rows:{table_name}"),
                    status: if ok {
                        "passed"
                    } else if required {
                        "failed"
                    } else {
                        "warning"
                    }
                    .into(),
                    expected: Some(format!(
                        "min={min_rows:?}, max={max_rows:?}, exact={exact_rows:?}"
                    )),
                    actual: Some(count.to_string()),
                    detail: None,
                });
                if !ok && required {
                    bail!("row-count expectation failed for {table_name}: got {count}")
                }
            }
        }
        let inv = result
            .database
            .as_ref()
            .context("database inventory unavailable")?;
        if cfg.verification.required_indexes.len() > 100
            || cfg.verification.required_constraints.len() > 100
        {
            bail!("at most 100 required indexes and constraints may be configured");
        }
        let invalid_index_names = if inv.invalid_indexes > 0 {
            run(&["exec",&name,"psql","-XAt","-U","postgres","-d",&target,"-c","SELECT n.nspname||'.'||t.relname||'.'||i.relname FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=i.relnamespace WHERE (NOT x.indisvalid OR NOT x.indisready) AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1 LIMIT 100"]).await?
        } else {
            String::new()
        };
        let unvalidated_names = if inv.unvalidated_constraints > 0 {
            run(&["exec",&name,"psql","-XAt","-U","postgres","-d",&target,"-c","SELECT n.nspname||'.'||t.relname||'.'||c.conname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE NOT c.convalidated AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1 LIMIT 100"]).await?
        } else {
            String::new()
        };
        for (id, count, required) in [
            (
                "valid_indexes",
                inv.invalid_indexes,
                cfg.verification.require_valid_indexes,
            ),
            (
                "validated_constraints",
                inv.unvalidated_constraints,
                cfg.verification.require_validated_constraints,
            ),
        ] {
            let none = count == 0;
            result.checks.push(Check {
                name: id.into(),
                status: if none {
                    "passed"
                } else if required {
                    "failed"
                } else {
                    "warning"
                }
                .into(),
                expected: Some("0".into()),
                actual: Some(count.to_string()),
                detail: if none {
                    None
                } else if id == "valid_indexes" {
                    Some(invalid_index_names.lines().collect::<Vec<_>>().join(", "))
                } else {
                    Some(unvalidated_names.lines().collect::<Vec<_>>().join(", "))
                },
            });
            if !none && required {
                bail!("required structural verification {id} found {count} issue(s)")
            }
        }
        for (kind, required, sql) in [
            (
                "index",
                &cfg.verification.required_indexes,
                "SELECT n.nspname||'.'||t.relname||'.'||i.relname FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=i.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND (n.nspname||'.'||t.relname||'.'||i.relname) IN (",
            ),
            (
                "constraint",
                &cfg.verification.required_constraints,
                "SELECT n.nspname||'.'||t.relname||'.'||c.conname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND (n.nspname||'.'||t.relname||'.'||c.conname) IN (",
            ),
        ] {
            if required.is_empty() {
                continue;
            }
            let names = required
                .iter()
                .map(|s| sql_literal(s))
                .collect::<Vec<_>>()
                .join(",");
            let query = format!("{sql}{names}) ORDER BY 1");
            let found = run(&[
                "exec", &name, "psql", "-XAt", "-U", "postgres", "-d", &target, "-c", &query,
            ])
            .await?;
            for expected in required {
                let present = found.lines().any(|x| x == expected);
                result.checks.push(Check {
                    name: format!("required_{kind}:{expected}"),
                    status: if present { "passed" } else { "failed" }.into(),
                    expected: Some("present".into()),
                    actual: Some(if present { "present" } else { "missing" }.into()),
                    detail: None,
                });
                if !present {
                    bail!("required {kind} {expected} is missing");
                }
            }
        }
        if cfg.verification.run_amcheck {
            run(&["exec",&name,"psql","-X","-v","ON_ERROR_STOP=1","-U","postgres","-d",&target,"-c","CREATE EXTENSION IF NOT EXISTS amcheck"]).await.context("pg_amcheck requires the amcheck extension available in the selected PostgreSQL image")?;
            run(&[
                "exec",
                &name,
                "pg_amcheck",
                "--database",
                &target,
                "--username",
                "postgres",
            ])
            .await
            .context("configured pg_amcheck could not run")?;
            result.checks.push(Check{name:"pg_amcheck".into(),status:"passed".into(),expected:None,actual:Some("checked supported relations".into()),detail:Some("pg_amcheck is a limited structural check, not a complete database integrity proof".into())});
        } else {
            result.checks.push(Check {
                name: "pg_amcheck".into(),
                status: "skipped".into(),
                expected: None,
                actual: None,
                detail: Some("not enabled in the expectation manifest".into()),
            });
        }
        for query in cfg.queries {
            let sql = format!(
                "BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '{check_timeout}s'; {}; ROLLBACK;",
                query.sql
            );
            let execution = run(&[
                "exec",
                &name,
                "psql",
                "-XAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "pbrc_verify",
                "-d",
                &target,
                "-c",
                &sql,
            ])
            .await;
            let actual = match execution {
                Ok(value) => value,
                Err(_) => {
                    result.checks.push(Check {
                        name: format!("assertion:{}", query.id),
                        status: if query.required { "error" } else { "skipped" }.into(),
                        expected: None,
                        actual: None,
                        detail: Some("assertion query failed; diagnostic output omitted".into()),
                    });
                    if query.required {
                        bail!("required SQL assertion {} could not be executed", query.id)
                    } else {
                        continue;
                    }
                }
            };
            if actual.len() >= 65536 {
                bail!(
                    "SQL assertion {} returned more than the 64 KiB result limit",
                    query.id
                );
            }
            let values: Vec<_> = actual.lines().filter(|x| !x.trim().is_empty()).collect();
            if values.len() != 1 {
                result.checks.push(Check {
                    name: format!("assertion:{}", query.id),
                    status: if query.required { "error" } else { "skipped" }.into(),
                    expected: None,
                    actual: None,
                    detail: Some("assertion must return exactly one row and one column".into()),
                });
                if query.required {
                    bail!(
                        "SQL assertion {} must return exactly one row and one column",
                        query.id
                    )
                } else {
                    continue;
                }
            }
            let value = values[0].trim();
            let ok = query
                .equals_integer
                .is_none_or(|v| value.parse::<i64>().ok() == Some(v))
                && query
                    .min_integer
                    .is_none_or(|v| value.parse::<i64>().is_ok_and(|n| n >= v))
                && query
                    .max_integer
                    .is_none_or(|v| value.parse::<i64>().is_ok_and(|n| n <= v))
                && query
                    .equals_boolean
                    .is_none_or(|v| value == if v { "t" } else { "f" })
                && query.equals_string.as_deref().is_none_or(|v| value == v);
            result.checks.push(Check {
                name: format!("assertion:{}", query.id),
                status: if ok {
                    "passed"
                } else if query.required {
                    "failed"
                } else {
                    "warning"
                }
                .into(),
                expected: None,
                actual: Some("(redacted)".into()),
                detail: Some(format!(
                    "{}: {}",
                    query.description.as_deref().unwrap_or("SQL assertion"),
                    if ok {
                        "assertion matched"
                    } else {
                        "assertion did not match"
                    }
                )),
            });
            if !ok && query.required {
                bail!("required SQL assertion {} failed", query.id)
            }
        }

        let structural_passed = result
            .checks
            .iter()
            .any(|c| c.name == "valid_indexes" && c.status == "passed")
            && result
                .checks
                .iter()
                .any(|c| c.name == "validated_constraints" && c.status == "passed");
        result.assurance_level = if application_assertions_required && structural_passed {
            "APPLICATION_VERIFIED"
        } else if structural_passed {
            "STRUCTURALLY_VERIFIED"
        } else {
            "RESTORABLE"
        }
        .into();
        result.status = "passed".into();
        verification_duration_ms = verification_start.elapsed().as_millis();
        Ok::<(), anyhow::Error>(())
    };
    let op = tokio::select! {result=operation=>result,signal=termination_signal()=>Err(anyhow::anyhow!("interrupted by {signal}"))};
    if let Err(e) = op {
        let message = format!("{e:#}");
        result.error_category = Some(classify_error(&message).into());
        if matches!(
            result.error_category.as_deref(),
            Some(
                "DOCKER_UNAVAILABLE"
                    | "CONTAINER_START_FAILED"
                    | "RESTORE_TIMEOUT"
                    | "VERIFICATION_TIMEOUT"
                    | "VERIFICATION_UNAVAILABLE"
                    | "INTERRUPTED"
            )
        ) {
            result.status = "incomplete".into();
        }
        result.error = Some(message);
    }
    if keep && result.status != "passed" && container_started {
        result.cleanup_status = "retained_on_failure".into();
    } else if container_started {
        match run(&["rm", "-f", &name]).await {
            Ok(_) => result.cleanup_status = "removed".into(),
            Err(e) => {
                result.cleanup_status = "failed".into();
                if result.status == "passed" {
                    result.status = "incomplete".into();
                    result.error_category = Some("CLEANUP_FAILED".into());
                    result.error = Some(format!("temporary container cleanup failed: {e:#}"));
                }
            }
        }
    } else {
        result.cleanup_status = "not_created".into();
    }
    result.restore_duration_ms = restore_duration_ms;
    result.readiness_duration_ms = readiness_duration_ms;
    result.backup_transfer_duration_ms = backup_transfer_duration_ms;
    result.verification_duration_ms = verification_duration_ms;
    result.total_duration_ms = total_start.elapsed().as_millis();
    result.finished_at = chrono::Utc::now().to_rfc3339();
    std::fs::create_dir_all(&report_dir)?;
    let dir = report_dir.join(&result.run_id);
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_vec_pretty(&result)?;
    std::fs::write(dir.join("report.json"), &json)?;
    std::fs::write(dir.join("report.md"), markdown(&result))?;
    Ok(result)
}
fn classify_error(message: &str) -> &'static str {
    let m = message.to_ascii_lowercase();
    if m.contains("restore jobs must be between")
        || m.contains("parallel restore jobs are supported only")
        || m.contains("single-transaction restore cannot be combined")
    {
        "INVALID_CONFIGURATION"
    } else if m.contains("no such file") || m.contains("cannot open") {
        "INPUT_NOT_FOUND"
    } else if m.contains("above the configured limit") || m.contains("exceeds configured limit") {
        "INPUT_SIZE_LIMIT"
    } else if m.contains("unsupported")
        || m.contains("unrecognized")
        || m.contains("invalid or unreadable")
        || m.contains("archive preflight failed")
        || m.contains("invalid or truncated gzip")
        || m.contains("backup is empty")
        || m.contains("directory is not a pg_dump directory archive")
        || m.contains("symbolic-link backup")
    {
        "UNSUPPORTED_FORMAT"
    } else if m.contains("fingerprint mismatch") {
        "ARTIFACT_FINGERPRINT_MISMATCH"
    } else if m.contains("interrupted") {
        "INTERRUPTED"
    } else if m.contains("timed out") || m.contains("timeout") {
        "RESTORE_TIMEOUT"
    } else if m.contains("docker cli unavailable")
        || m.contains("daemon is unavailable")
        || m.contains("permission denied")
    {
        "DOCKER_UNAVAILABLE"
    } else if m.contains("pg_amcheck") || m.contains("extension") {
        "VERIFICATION_UNAVAILABLE"
    } else if m.contains("docker") || m.contains("container") {
        "CONTAINER_START_FAILED"
    } else if m.contains("expectation")
        || m.contains("assertion")
        || m.contains("index")
        || m.contains("constraint")
    {
        "VERIFICATION_FAILED"
    } else {
        "RESTORE_FAILED"
    }
}
fn tokio_handle_write(stdin: &mut tokio::process::ChildStdin, bytes: &[u8]) -> Result<()> {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(async { stdin.write_all(bytes).await })?;
    Ok(())
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Expectations {
    metadata: Option<ManifestMetadata>,
    #[serde(default)]
    tables: Vec<TableExpectation>,
    #[serde(default)]
    row_counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    queries: Vec<QueryExpectation>,
    #[serde(default)]
    verification: VerificationPolicy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestMetadata {
    name: String,
    description: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum TableExpectation {
    Name(String),
    Detailed(DetailedTableExpectation),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedTableExpectation {
    name: String,
    #[serde(default = "default_true")]
    required: bool,
    min_rows: Option<u64>,
    max_rows: Option<u64>,
    exact_rows: Option<u64>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VerificationPolicy {
    #[serde(default)]
    require_nonempty_database: bool,
    #[serde(default)]
    require_valid_indexes: bool,
    #[serde(default)]
    require_validated_constraints: bool,
    #[serde(default)]
    run_amcheck: bool,
    #[serde(default)]
    required_indexes: Vec<String>,
    #[serde(default)]
    required_constraints: Vec<String>,
    #[serde(default)]
    required_schemas: Vec<String>,
    #[serde(default)]
    required_extensions: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryExpectation {
    id: String,
    description: Option<String>,
    sql: String,
    equals_integer: Option<i64>,
    min_integer: Option<i64>,
    max_integer: Option<i64>,
    equals_boolean: Option<bool>,
    equals_string: Option<String>,
    #[serde(default = "default_true")]
    required: bool,
}
struct CheckOptions {
    image: String,
    expectations: Option<Expectations>,
    report_dir: PathBuf,
    timeout: u64,
    keep: bool,
    expected_sha256: Option<String>,
    max_backup_bytes: u64,
    strict: bool,
    memory_limit: String,
    cpu_limit: f64,
    check_timeout: u64,
    startup_timeout: u64,
    jobs: usize,
    single_transaction: bool,
    quiet: bool,
    verbose: bool,
}
fn default_true() -> bool {
    true
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    postgres_image: Option<String>,
    postgres_major: Option<String>,
    report_dir: Option<PathBuf>,
    timeout: Option<u64>,
    expectations: Option<PathBuf>,
    expected_sha256: Option<String>,
    max_backup_bytes: Option<u64>,
    memory_limit: Option<String>,
    cpu_limit: Option<f64>,
    check_timeout: Option<u64>,
    startup_timeout: Option<u64>,
    jobs: Option<usize>,
    single_transaction: Option<bool>,
}
fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn quote_qualified(s: &str) -> Result<String> {
    let parts: Vec<_> = s.split('.').collect();
    if parts.is_empty()
        || parts.len() > 2
        || parts
            .iter()
            .any(|p| p.is_empty() || p.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '_')))
    {
        bail!("invalid table identifier `{s}`; use table or schema.table")
    }
    Ok(parts
        .into_iter()
        .map(quote_ident)
        .collect::<Vec<_>>()
        .join("."))
}
fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
fn validate_expectations(cfg: &Expectations) -> Result<()> {
    let mut ids = std::collections::HashSet::new();
    let mut table_names = std::collections::HashSet::new();
    if cfg.tables.len() > 1000 || cfg.row_counts.len() > 1000 || cfg.queries.len() > 100 {
        bail!("expectations exceed the limit of 1,000 tables/counts or 100 SQL assertions");
    }
    if cfg
        .metadata
        .as_ref()
        .is_some_and(|m| m.name.trim().is_empty())
    {
        bail!("expectation metadata.name must be nonempty");
    }
    for table in cfg.row_counts.keys() {
        quote_qualified(table)?;
    }
    for table in &cfg.tables {
        let (name, min, max, exact) = match table {
            TableExpectation::Name(n) => (n, None, None, None),
            TableExpectation::Detailed(t) => (&t.name, t.min_rows, t.max_rows, t.exact_rows),
        };
        quote_qualified(name)?;
        if !table_names.insert(name) {
            bail!("table `{name}` is listed more than once");
        }
        if min.is_some_and(|v| max.is_some_and(|m| v > m)) {
            bail!("table `{name}` has min_rows greater than max_rows");
        }
        if exact.is_some() && (min.is_some() || max.is_some()) {
            bail!("table `{name}` cannot combine exact_rows with row bounds");
        }
    }
    for (category, values) in [
        ("index", &cfg.verification.required_indexes),
        ("constraint", &cfg.verification.required_constraints),
        ("schema", &cfg.verification.required_schemas),
        ("extension", &cfg.verification.required_extensions),
    ] {
        if values.len() > 100 || values.iter().any(|x| x.trim().is_empty()) {
            bail!(
                "required {category} names must be nonempty and no more than 100 may be configured"
            );
        }
    }
    for q in &cfg.queries {
        if q.id.trim().is_empty() || !ids.insert(&q.id) {
            bail!("SQL assertion IDs must be nonempty and unique: `{}`", q.id);
        }
        if q.sql.trim().is_empty() {
            bail!("SQL assertion `{}` has empty SQL", q.id);
        }
        if q.sql.len() > 16384 {
            bail!("SQL assertion `{}` exceeds the 16 KiB query limit", q.id);
        }
        let policies = [
            q.equals_integer.is_some(),
            q.min_integer.is_some(),
            q.max_integer.is_some(),
            q.equals_boolean.is_some(),
            q.equals_string.is_some(),
        ]
        .into_iter()
        .filter(|x| *x)
        .count();
        if policies != 1 {
            bail!("SQL assertion `{}` must define one comparison", q.id);
        }
        if q.sql.contains(';') {
            bail!(
                "SQL assertion `{}` must contain one statement without semicolons",
                q.id
            );
        }
        let first = q.sql.split_whitespace().next().unwrap_or_default();
        if !first.eq_ignore_ascii_case("select") && !first.eq_ignore_ascii_case("with") {
            bail!("SQL assertion `{}` must be a SELECT or WITH query", q.id);
        }
    }
    Ok(())
}
fn validate_memory_limit(value: &str) -> Result<()> {
    let text = value.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .context("memory limit must be an integer size such as 2g")?;
    let (number, unit) = text.split_at(split);
    if number.parse::<u64>().unwrap_or(0) == 0
        || !matches!(
            unit.to_ascii_lowercase().as_str(),
            "b" | "k" | "kb" | "m" | "mb" | "g" | "gb" | "t" | "tb"
        )
    {
        bail!("invalid Docker memory limit `{value}`; use a positive integer with b, k, m, g, or t")
    }
    Ok(())
}
fn load_expectations(path: &Path) -> Result<Expectations> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading expectations {}", path.display()))?;
    let cfg: Expectations = toml::from_str(&source).context("parsing expectations TOML")?;
    validate_expectations(&cfg).context("invalid expectations configuration")?;
    Ok(cfg)
}
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star, mut retry) = (None, 0usize);
    let pb = pattern.as_bytes();
    let vb = value.as_bytes();
    while v < vb.len() {
        if p < pb.len() && (pb[p] == b'?' || pb[p] == vb[v]) {
            p += 1;
            v += 1
        } else if p < pb.len() && pb[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v
        } else if let Some(s) = star {
            p = s + 1;
            retry += 1;
            v = retry
        } else {
            return false;
        }
    }
    while p < pb.len() && pb[p] == b'*' {
        p += 1
    }
    p == pb.len()
}
fn is_backup_candidate(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if metadata.is_file() {
        return true;
    }
    if metadata.is_dir() {
        return std::fs::symlink_metadata(path.join("toc.dat"))
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink());
    }
    false
}
fn markdown(r: &CheckResult) -> String {
    let mut out = format!(
        "# PostgreSQL recovery report\n\n- Status: **{}**\n- Assurance: **{}**\n- Run: `{}`\n- Backup: `{}`\n- Format: {}\n- Fingerprint (`{}`): `{}`\n- PostgreSQL server: {}\n- Expectations: {}\n- Application objects found: {}\n",
        r.status,
        r.assurance_level,
        r.run_id,
        r.artifact.path,
        r.artifact.format,
        r.artifact.fingerprint_algorithm,
        r.artifact.sha256,
        r.postgres_version.as_deref().unwrap_or("unavailable"),
        r.expectations_name.as_deref().unwrap_or("none"),
        r.tables.len()
    );
    out.push_str(&format!("\n## Timing\n\n- Container startup: {} ms\n- Database readiness: {} ms\n- Backup transfer: {} ms\n- Restore: {} ms\n- Verification: {} ms\n- Total: {} ms\n- Cleanup: {}\n",r.container_startup_duration_ms,r.readiness_duration_ms,r.backup_transfer_duration_ms,r.restore_duration_ms,r.verification_duration_ms,r.total_duration_ms,r.cleanup_status));
    if let Some(description) = &r.expectations_description {
        out.push_str(&format!("\nExpectation manifest: {}\n", description));
    }
    if let Some(db) = &r.database {
        out.push_str(&format!("\n## Database inventory\n\n- Schemas: {}\n- Tables: {}\n- Views: {}\n- Materialized views: {}\n- Indexes: {} (invalid: {})\n- Constraints: {} (unvalidated: {})\n- Sequences: {}\n- Extensions: {}\n",db.schemas,db.tables,db.views,db.materialized_views,db.indexes,db.invalid_indexes,db.constraints,db.unvalidated_constraints,db.sequences,if db.extensions.is_empty(){"none".into()}else{db.extensions.join(", ")}));
    }
    out.push_str("\n## Verification results\n\n");
    for check in &r.checks {
        out.push_str(&format!(
            "- **{}** `{}`{}{}\n",
            check.status.to_uppercase(),
            check.name,
            check
                .expected
                .as_deref()
                .map(|x| format!("; expected {x}"))
                .unwrap_or_default(),
            check
                .actual
                .as_deref()
                .map(|x| format!("; actual {x}"))
                .unwrap_or_default()
        ));
    }
    if let Some(error) = &r.error {
        out.push_str(&format!("\n## Error\n\n{}\n", error));
    }
    out.push_str("\nRestore time is measured in this isolated test environment and does not guarantee production RTO.\n");
    out
}
#[tokio::main]
async fn main() {
    if let Err(e) = entry().await {
        let message = format!("{e:#}");
        eprintln!("pbrc: {message}");
        let lower = message.to_ascii_lowercase();
        let code = if lower.contains("unsupported")
            || lower.contains("unrecognized")
            || lower.contains("not found")
            || lower.contains("cannot open")
            || lower.contains("backup is empty")
            || lower.contains("symbolic-link")
            || lower.contains("not a pg_dump directory archive")
            || lower.contains("gzip")
        {
            4
        } else if lower.contains("docker") || lower.contains("daemon") {
            3
        } else if lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("interrupted")
        {
            5
        } else if lower.contains("invalid")
            || lower.contains("parsing")
            || lower.contains("requires")
            || lower.contains("conflict")
            || lower.contains("configuration")
            || lower.contains("must be between")
            || lower.contains("cannot set both")
        {
            2
        } else {
            6
        };
        std::process::exit(code)
    }
}
async fn entry() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect { backup, json } => {
            let a = artifact(&backup)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&a)?)
            } else {
                println!(
                    "INSPECTED (this is not restore verification)\nPath: {}\nFormat: {}\nSize: {} bytes\nSHA-256: {}\nModified: {}",
                    a.path,
                    a.format,
                    a.size_bytes,
                    a.sha256,
                    a.modified.as_deref().unwrap_or("unknown")
                );
            }
        }
        Commands::Doctor { postgres_image } => {
            let v = Command::new("docker")
                .arg("version")
                .output()
                .await
                .context("Docker CLI unavailable; install Docker and start its daemon")?;
            if !v.status.success() {
                bail!("Docker daemon is unavailable; start Docker")
            };
            println!("Docker CLI ............... OK\nDocker daemon ............ OK");
            let info = run(&["info", "--format", "{{.ServerVersion}}|{{.Architecture}}"])
                .await
                .context("Docker daemon is reachable but docker info failed")?;
            println!("Docker server ............ {}", info);
            run(&["image", "inspect", &postgres_image]).await?;
            println!("PostgreSQL image ......... OK ({postgres_image})");
            let name = format!("pbrc-doctor-{}", &Uuid::new_v4().to_string()[..8]);
            run(&[
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "--network",
                "none",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                &postgres_image,
            ])
            .await
            .context("could not start isolated PostgreSQL container")?;
            let smoke = async {
                wait_postgres(&name, 60).await?;
                let answer = run(&[
                    "exec", &name, "psql", "-XAt", "-U", "postgres", "-d", "postgres", "-c",
                    "SELECT 1",
                ])
                .await?;
                if answer.trim() != "1" {
                    bail!("PostgreSQL smoke query returned an unexpected result")
                };
                Ok::<(), anyhow::Error>(())
            };
            let smoke = tokio::select! {result=smoke=>result,signal=termination_signal()=>Err(anyhow::anyhow!("interrupted by {signal}"))};
            let cleanup = run(&["rm", "-f", &name]).await;
            smoke?;
            cleanup?;
            println!(
                "Container execution ...... OK\nRequired permissions ...... OK\nEnvironment ready."
            );
        }
        Commands::Check(args) => {
            let CheckArgs {
                backup,
                directory,
                latest,
                glob,
                config,
                postgres_image,
                postgres_major,
                expectations,
                report_dir,
                format,
                json,
                ci,
                strict,
                timeout,
                startup_timeout,
                check_timeout,
                jobs,
                single_transaction,
                no_single_transaction,
                quiet,
                verbose,
                no_color: _,
                expected_sha256,
                max_backup_bytes,
                memory_limit,
                cpu_limit,
                keep_on_failure,
            } = *args;
            let config = if let Some(path) = config {
                let src = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                toml::from_str::<AppConfig>(&src).context("parsing pbrc config TOML")?
            } else {
                AppConfig::default()
            };
            if config.postgres_image.is_some() && config.postgres_major.is_some() {
                bail!("config cannot set both postgres_image and postgres_major");
            }
            let expectations_path = expectations.or(config.expectations);
            let expectations = expectations_path
                .as_deref()
                .map(load_expectations)
                .transpose()?;
            if strict
                && expectations.as_ref().is_none_or(|e| {
                    (e.tables.is_empty() && e.row_counts.is_empty() && e.queries.is_empty())
                        || (e.tables.iter().all(|t| {
                            matches!(
                                t,
                                TableExpectation::Detailed(DetailedTableExpectation {
                                    required: false,
                                    ..
                                })
                            )
                        }) && e.row_counts.is_empty()
                            && e.queries.iter().all(|q| !q.required))
                })
            {
                bail!("--strict requires application-level table, row-count, or SQL assertions");
            }
            let path = if let Some(p) = backup {
                p
            } else {
                let d = directory.context("provide --backup or --directory with --latest")?;
                if !latest {
                    bail!("--directory requires --latest")
                };
                let pattern = glob.as_deref().unwrap_or("*");
                std::fs::read_dir(d)?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        is_backup_candidate(p)
                            && p.file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| wildcard_match(pattern, n))
                    })
                    .max_by_key(|p| {
                        (
                            std::fs::metadata(p).and_then(|m| m.modified()).ok(),
                            p.clone(),
                        )
                    })
                    .context("no backup candidates found")?
            };
            let image = if let Some(major) = postgres_major.or_else(|| {
                if postgres_image.is_none() {
                    config.postgres_major.clone()
                } else {
                    None
                }
            }) {
                if !matches!(major.as_str(), "16" | "17" | "18") {
                    bail!("supported --postgres-major values are 16, 17, and 18");
                }
                format!("postgres:{major}-alpine")
            } else {
                postgres_image
                    .or(config.postgres_image)
                    .unwrap_or_else(|| "postgres:17-alpine".into())
            };
            let report_dir = report_dir
                .or(config.report_dir)
                .unwrap_or_else(|| PathBuf::from("reports"));
            let timeout = timeout.or(config.timeout).unwrap_or(600);
            let startup_timeout = startup_timeout.or(config.startup_timeout).unwrap_or(90);
            if startup_timeout == 0 || startup_timeout > 3600 {
                bail!("startup timeout must be between 1 and 3600 seconds");
            }
            let check_timeout = check_timeout.or(config.check_timeout).unwrap_or(30);
            if check_timeout == 0 || check_timeout > 86400 {
                bail!("check timeout must be between 1 and 86400 seconds");
            }
            let jobs = jobs.or(config.jobs).unwrap_or(1);
            let single_transaction = if no_single_transaction {
                false
            } else if single_transaction {
                true
            } else {
                config.single_transaction.unwrap_or(false)
            };
            let expected_sha256 = expected_sha256.or(config.expected_sha256);
            if expected_sha256
                .as_deref()
                .is_some_and(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                bail!("invalid expected SHA-256; provide exactly 64 hexadecimal characters");
            }
            let max_backup_bytes = max_backup_bytes
                .or(config.max_backup_bytes)
                .unwrap_or(10 * 1024 * 1024 * 1024);
            let memory_limit = memory_limit
                .or(config.memory_limit)
                .unwrap_or_else(|| "2g".into());
            validate_memory_limit(&memory_limit)?;
            let cpu_limit = cpu_limit.or(config.cpu_limit).unwrap_or(2.0);
            if !cpu_limit.is_finite() || cpu_limit <= 0.0 {
                bail!("CPU limit must be a finite positive number");
            }
            let r = check(
                path,
                CheckOptions {
                    image,
                    expectations,
                    report_dir: report_dir.clone(),
                    timeout,
                    keep: keep_on_failure,
                    expected_sha256,
                    max_backup_bytes,
                    strict,
                    memory_limit,
                    cpu_limit,
                    check_timeout,
                    startup_timeout,
                    jobs,
                    single_transaction,
                    quiet: quiet || ci,
                    verbose,
                },
            )
            .await?;
            if json || matches!(format, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&r)?)
            } else if quiet || ci {
                // Quiet and CI suppress the human-readable summary.
            } else if matches!(format, OutputFormat::Markdown) {
                print!("{}", markdown(&r));
            } else {
                println!(
                    "Status: {}\nBackup: {}\nFormat: {}\nTables: {}\nRestore time: {} ms\nReport: {}/{}/report.json",
                    r.status,
                    r.artifact.path,
                    r.artifact.format,
                    r.tables.len(),
                    r.restore_duration_ms,
                    report_dir.display(),
                    r.run_id
                );
            }
            if r.status != "passed" {
                let code = if r.status == "incomplete" {
                    if r.error_category.as_deref() == Some("DOCKER_UNAVAILABLE")
                        || r.error_category.as_deref() == Some("CONTAINER_START_FAILED")
                    {
                        3
                    } else {
                        5
                    }
                } else if r.error_category.as_deref() == Some("INVALID_CONFIGURATION") {
                    2
                } else if matches!(
                    r.error_category.as_deref(),
                    Some("INPUT_NOT_FOUND" | "UNSUPPORTED_FORMAT" | "INPUT_SIZE_LIMIT")
                ) {
                    4
                } else {
                    1
                };
                std::process::exit(code)
            }
        }
        Commands::Demo {
            out,
            postgres_image,
        } => {
            std::fs::create_dir_all(&out)?;
            let source = format!("pbrc-demo-{}", &Uuid::new_v4().to_string()[..8]);
            let good = out.join("healthy.dump");
            create_demo_backup(
                &postgres_image,
                &source,
                &good,
                "CREATE TABLE customers(id int primary key, email text unique); INSERT INTO customers VALUES (1,'demo@example.test'),(2,'ops@example.test'); CREATE TABLE invoices(id int primary key, customer_id int references customers(id), amount_cents int); INSERT INTO invoices VALUES (10,1,1250),(11,2,980);",
                "custom",
            ).await?;
            let exp = out.join("expectations.toml");
            std::fs::write(
                &exp,
                "tables = [\"public.customers\", \"public.invoices\"]\n[verification]\nrequire_nonempty_database = true\nrequire_valid_indexes = true\nrequire_validated_constraints = true\nrun_amcheck = false\n[row_counts]\n\"public.customers\" = 2\n\"public.invoices\" = 2\n[[queries]]\nid = \"customers_present\"\nsql = \"SELECT count(*) FROM public.customers\"\nmin_integer = 1\n",
            )?;
            let goodr = check(
                good.clone(),
                CheckOptions {
                    image: postgres_image.clone(),
                    expectations: Some(load_expectations(&exp)?),
                    report_dir: out.join("reports"),
                    timeout: 300,
                    keep: false,
                    expected_sha256: None,
                    max_backup_bytes: 10 * 1024 * 1024 * 1024,
                    strict: true,
                    memory_limit: "2g".into(),
                    cpu_limit: 2.0,
                    check_timeout: 30,
                    startup_timeout: 90,
                    jobs: 1,
                    single_transaction: false,
                    quiet: false,
                    verbose: false,
                },
            )
            .await?;
            if goodr.status != "passed" {
                bail!(
                    "healthy demo restore did not pass: {}",
                    goodr.error.as_deref().unwrap_or("unknown failure")
                );
            }
            let mut format_paths = vec![
                ("tar", out.join("healthy.tar")),
                ("directory", out.join("healthy-directory")),
                ("sql", out.join("healthy.sql")),
            ];
            for (kind, path) in &format_paths {
                let name = format!("pbrc-format-{}-{}", kind, &Uuid::new_v4().to_string()[..8]);
                create_demo_backup(&postgres_image,&name,path,"CREATE TABLE customers(id int primary key, email text unique); INSERT INTO customers VALUES (1,'demo@example.test'),(2,'ops@example.test'); CREATE TABLE invoices(id int primary key, customer_id int references customers(id), amount_cents int); INSERT INTO invoices VALUES (10,1,1250),(11,2,980);",kind).await?;
            }
            let gzip_path = out.join("healthy.sql.gz");
            {
                let mut input = File::open(out.join("healthy.sql"))?;
                let mut encoder = flate2::write::GzEncoder::new(
                    File::create(&gzip_path)?,
                    flate2::Compression::default(),
                );
                std::io::copy(&mut input, &mut encoder)?;
                encoder.finish()?;
            }
            format_paths.push(("gzip_sql", gzip_path));
            for (label, path) in format_paths {
                let format_result = check(
                    path,
                    CheckOptions {
                        image: postgres_image.clone(),
                        expectations: Some(load_expectations(&exp)?),
                        report_dir: out.join("reports"),
                        timeout: 300,
                        keep: false,
                        expected_sha256: None,
                        max_backup_bytes: 10 * 1024 * 1024 * 1024,
                        strict: true,
                        memory_limit: "2g".into(),
                        cpu_limit: 2.0,
                        check_timeout: 30,
                        startup_timeout: 90,
                        jobs: 1,
                        single_transaction: false,
                        quiet: false,
                        verbose: false,
                    },
                )
                .await?;
                if format_result.status != "passed" {
                    bail!(
                        "{label} backup restore failed: {}",
                        format_result.error.as_deref().unwrap_or("unknown failure")
                    );
                }
            }
            let bad = out.join("corrupted.dump");
            let bytes = std::fs::read(&good)?;
            std::fs::write(&bad, &bytes[..bytes.len() / 2])?;
            let badr = check(
                bad,
                CheckOptions {
                    image: postgres_image.clone(),
                    expectations: None,
                    report_dir: out.join("reports"),
                    timeout: 120,
                    keep: false,
                    expected_sha256: None,
                    max_backup_bytes: 10 * 1024 * 1024 * 1024,
                    strict: false,
                    memory_limit: "2g".into(),
                    cpu_limit: 2.0,
                    check_timeout: 30,
                    startup_timeout: 90,
                    jobs: 1,
                    single_transaction: false,
                    quiet: false,
                    verbose: false,
                },
            )
            .await?;
            if badr.status == "passed" {
                bail!("corrupted demo archive unexpectedly passed restore verification");
            }
            let incomplete = out.join("incomplete.dump");
            let partial = format!("pbrc-partial-{}", &Uuid::new_v4().to_string()[..8]);
            create_demo_backup(
                &postgres_image,
                &partial,
                &incomplete,
                "CREATE TABLE customers(id int primary key, email text); INSERT INTO customers VALUES (1,'partial@example.test');",
                "custom",
            ).await?;
            let incompleter = check(
                incomplete,
                CheckOptions {
                    image: postgres_image,
                    expectations: Some(load_expectations(&exp)?),
                    report_dir: out.join("reports"),
                    timeout: 120,
                    keep: false,
                    expected_sha256: None,
                    max_backup_bytes: 10 * 1024 * 1024 * 1024,
                    strict: false,
                    memory_limit: "2g".into(),
                    cpu_limit: 2.0,
                    check_timeout: 30,
                    startup_timeout: 90,
                    jobs: 1,
                    single_transaction: false,
                    quiet: false,
                    verbose: false,
                },
            )
            .await?;
            if incompleter.status == "passed" {
                bail!("logically incomplete demo backup unexpectedly passed expectations");
            }
            println!(
                "Demo reports: {}\nHealthy restore: {}\nCorrupted backup: {}\nIncomplete scenario: {}",
                out.display(),
                goodr.status,
                badr.status,
                incompleter.status
            );
        }
        Commands::Report { command } => {
            let (p, show) = match command {
                ReportCommand::Show { path } => (path, true),
                ReportCommand::Summary { path } => (path, false),
            };
            let r: CheckResult = serde_json::from_slice(&std::fs::read(p)?)?;
            if show {
                print!("{}", markdown(&r));
            } else {
                let passed = r.checks.iter().filter(|c| c.status == "passed").count();
                let failed = r
                    .checks
                    .iter()
                    .filter(|c| c.status == "failed" || c.status == "error")
                    .count();
                let skipped = r.checks.iter().filter(|c| c.status == "skipped").count();
                println!(
                    "{} — {}\nBackup: {} ({}, {} bytes)\nFingerprint: {}\nRestore: {} ms\nChecks: {} passed, {} failed, {} skipped\nCleanup: {}",
                    r.status.to_uppercase(),
                    r.assurance_level,
                    r.artifact.path,
                    r.artifact.format,
                    r.artifact.size_bytes,
                    r.artifact.sha256,
                    r.restore_duration_ms,
                    passed,
                    failed,
                    skipped,
                    r.cleanup_status
                );
            }
        }
        Commands::Cleanup { run_id, stale, yes } => {
            if run_id.is_none() && !stale {
                bail!("provide --run-id or --stale")
            };
            let run_filter = run_id.map(|x| format!("label=io.pbrc.run={x}"));
            let mut list_args = vec!["ps", "-aq", "--filter", "label=io.pbrc.managed=true"];
            if let Some(filter) = run_filter.as_deref() {
                list_args.extend(["--filter", filter]);
            }
            let found = run(&list_args).await?;
            let ids = if stale {
                let mut stale_ids = Vec::new();
                for id in found.lines().filter(|id| !id.is_empty()) {
                    let created = match run(&["inspect", "--format", "{{.Created}}", id]).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let created = match chrono::DateTime::parse_from_rfc3339(&created) {
                        Ok(v) => v.with_timezone(&chrono::Utc),
                        Err(_) => continue,
                    };
                    if chrono::Utc::now() - created > chrono::Duration::hours(24) {
                        stale_ids.push(id.to_string());
                    }
                }
                stale_ids.join("\n")
            } else {
                found
            };
            if !yes {
                println!("Containers to remove:\n{ids}\nPass --yes to confirm.");
                return Ok(());
            }
            for id in ids.lines().filter(|x| !x.is_empty()) {
                run(&["rm", "-f", id]).await?;
            }
            println!(
                "Removed {} project-owned container(s).",
                ids.lines().filter(|x| !x.is_empty()).count()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_pg_dump_custom_signature() {
        let path = std::env::temp_dir().join(format!("pbrc-test-{}.dump", Uuid::new_v4()));
        std::fs::write(&path, b"PGDMP\x01\x0f\x00\x08").unwrap();
        assert_eq!(detect(&path).unwrap(), "custom");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_empty_artifact() {
        let path = std::env::temp_dir().join(format!("pbrc-test-{}.dump", Uuid::new_v4()));
        std::fs::write(&path, []).unwrap();
        assert!(detect(&path).unwrap_err().to_string().contains("empty"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validates_gzip_streams_and_rejects_truncation() {
        let path = std::env::temp_dir().join(format!("pbrc-gzip-{}.sql.gz", Uuid::new_v4()));
        let mut bytes = Vec::new();
        for sql in [b"SELECT 1;".as_slice(), b"SELECT 2;".as_slice()] {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, sql).unwrap();
            bytes.extend(encoder.finish().unwrap());
        }
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(detect(&path).unwrap(), "gzip_sql");
        validate_gzip(&path, 1024).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        assert!(validate_gzip(&path, 1024).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn quotes_identifiers() {
        assert_eq!(quote_ident("odd\"table"), "\"odd\"\"table\"");
    }

    #[test]
    fn wildcard_selects_deterministically() {
        assert!(wildcard_match("app-*.dump", "app-2026.dump"));
        assert!(!wildcard_match("app-*.dump", "other.dump"));
    }

    #[test]
    fn parses_and_validates_expectation_manifest() {
        let manifest: Expectations = toml::from_str("tables = [\"public.customers\"]\n[[queries]]\nid = \"row-total\"\nsql = \"SELECT count(*) FROM public.customers\"\nmin_integer = 1\n").unwrap();
        validate_expectations(&manifest).unwrap();
        let invalid: Expectations = toml::from_str(
            "[[queries]]\nid = \"x\"\nsql = \"SELECT 1\"\nequals_integer = 1\nmax_integer = 2\n",
        )
        .unwrap();
        assert!(validate_expectations(&invalid).is_err());
    }

    #[test]
    fn checked_in_examples_parse() {
        let cfg: AppConfig = toml::from_str(include_str!("../examples/pbrc.toml")).unwrap();
        assert_eq!(cfg.postgres_major.as_deref(), Some("17"));
        let manifest: Expectations =
            toml::from_str(include_str!("../examples/expectations.toml")).unwrap();
        validate_expectations(&manifest).unwrap();
    }

    #[test]
    fn directory_fingerprint_is_stable_and_tracks_tree_paths() {
        let root = std::env::temp_dir().join(format!("pbrc-tree-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("toc.dat"), b"archive index").unwrap();
        std::fs::write(root.join("1.dat"), b"table contents").unwrap();
        let first = artifact(&root).unwrap();
        let second = artifact(&root).unwrap();
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(first.fingerprint_algorithm, "sha256-tree-v1");
        std::fs::rename(root.join("1.dat"), root.join("2.dat")).unwrap();
        assert_ne!(first.sha256, artifact(&root).unwrap().sha256);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cli_accepts_primary_check_invocation() {
        let cli = Cli::try_parse_from([
            "pbrc",
            "check",
            "--backup",
            "sample.dump",
            "--postgres-major",
            "17",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::Check(_)));
    }

    #[test]
    fn cli_rejects_ambiguous_backup_selection_and_output_modes() {
        assert!(Cli::try_parse_from(["pbrc", "check", "--backup", "a.dump", "--latest"]).is_err());
        assert!(
            Cli::try_parse_from([
                "pbrc",
                "check",
                "--directory",
                "backups",
                "--backup",
                "a.dump",
                "--latest"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "pbrc",
                "check",
                "--backup",
                "a.dump",
                "--quiet",
                "--verbose"
            ])
            .is_err()
        );
    }

    #[test]
    fn classifies_preflight_errors_as_input_failures() {
        assert_eq!(classify_error("backup is empty"), "UNSUPPORTED_FORMAT");
        assert_eq!(
            classify_error("decompressed SQL exceeds configured limit of 1 bytes"),
            "INPUT_SIZE_LIMIT"
        );
        assert_eq!(
            classify_error("PostgreSQL archive preflight failed: corrupt"),
            "UNSUPPORTED_FORMAT"
        );
        assert_eq!(
            classify_error("invalid or truncated gzip SQL stream"),
            "UNSUPPORTED_FORMAT"
        );
        assert_eq!(
            classify_error("restore jobs must be between 1 and 32"),
            "INVALID_CONFIGURATION"
        );
    }
}
