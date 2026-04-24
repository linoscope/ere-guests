//! Host-side debug runner for stateless validator guest fixtures.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail, ensure};
use clap::{Parser, ValueEnum};
use guest::{Guest, Platform};
use rayon::{ThreadPoolBuilder, prelude::*};
use serde::Deserialize;
use stateless::StatelessInput;
use stateless_validator_ethrex::guest::{
    StatelessValidatorEthrexGuest, StatelessValidatorEthrexInput,
};
use stateless_validator_reth::guest::{
    StatelessValidatorOutput, StatelessValidatorRethGuest, StatelessValidatorRethInput,
};
use tracing_subscriber::EnvFilter;

/// CLI options for the stateless validator debug runner.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "stateless-validator-debug",
    about = "Run stateless validator guest fixtures directly on the host.",
    long_about = None,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Guest program to run.
    #[arg(long, value_enum)]
    pub guest: GuestKind,
    /// Warn and continue when fixture success does not match guest output.
    #[arg(long)]
    pub allow_success_mismatch: bool,
    /// Number of fixtures to run in parallel.
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
    /// Path to a fixture file or directory.
    pub path: PathBuf,
}

/// Stateless validator guest selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GuestKind {
    /// Run the Reth stateless validator guest.
    Reth,
    /// Run the Ethrex stateless validator guest.
    Ethrex,
}

impl GuestKind {
    fn run_fixture(self, fixture: &StatelessValidatorFixture) -> anyhow::Result<RunSummary> {
        let output: StatelessValidatorOutput = match self {
            Self::Reth => {
                let input =
                    StatelessValidatorRethInput::new(&fixture.stateless_input, fixture.success)?;
                StatelessValidatorRethGuest::compute::<StdoutNoopPlatform>(input)
            }
            Self::Ethrex => {
                let input =
                    StatelessValidatorEthrexInput::new(&fixture.stateless_input, fixture.success)?;
                StatelessValidatorEthrexGuest::compute::<StdoutNoopPlatform>(input)
            }
        };

        Ok(RunSummary {
            fixture_name: fixture.name.clone(),
            guest: self,
            expected_success: fixture.success,
            actual_success: output.successful_block_validation,
            new_payload_request_root: output.new_payload_request_root,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reth => "reth",
            Self::Ethrex => "ethrex",
        }
    }
}

/// Deserialized JSON fixture supported by the debug runner.
#[derive(Debug, Clone, Deserialize)]
pub struct StatelessValidatorFixture {
    /// Human-readable fixture identifier.
    pub name: String,
    /// Stateless input consumed by the host-side input builders.
    pub stateless_input: StatelessInput,
    /// Expected validation outcome.
    pub success: bool,
}

/// Summary of one guest execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// Name of the fixture that ran.
    pub fixture_name: String,
    /// Guest program that was executed.
    pub guest: GuestKind,
    /// Expected guest success from the fixture.
    pub expected_success: bool,
    /// Actual guest success reported by the guest output.
    pub actual_success: bool,
    /// The resulting new payload request root.
    pub new_payload_request_root: [u8; 32],
}

#[derive(Debug)]
struct FixtureRun {
    path: PathBuf,
    summary: RunSummary,
}

impl std::fmt::Display for RunSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fixture={} guest={} expected_success={} actual_success={} new_payload_request_root=0x{}",
            self.fixture_name,
            self.guest.as_str(),
            self.expected_success,
            self.actual_success,
            encode_hex(&self.new_payload_request_root),
        )
    }
}

/// A no-op platform for host-side guest execution that forwards debug messages to stdout.
#[derive(Debug)]
pub struct StdoutNoopPlatform;

impl Platform for StdoutNoopPlatform {
    #[allow(unreachable_code)]
    fn read_whole_input() -> impl std::ops::Deref<Target = [u8]> {
        panic!("Can't read input in StdoutNoopPlatform");
        &[] as &[u8]
    }

    fn write_whole_output(_: &[u8]) {
        panic!("Can't write output in StdoutNoopPlatform");
    }

    fn print(message: &str) {
        println!("{message}");
        let _ = io::stdout().flush();
    }
}

/// Entry point for the debug runner binary.
pub fn main_entry() -> anyhow::Result<()> {
    init_tracing();
    execute(Cli::parse(), |summary| println!("{summary}"))
}

/// Executes one or more fixtures and reports each summary via `on_summary`.
pub fn execute(cli: Cli, mut on_summary: impl FnMut(&RunSummary)) -> anyhow::Result<()> {
    let fixture_paths = collect_fixture_paths(&cli.path)?;
    ensure!(cli.jobs > 0, "--jobs must be greater than 0");
    let runs = run_fixtures(cli.guest, cli.jobs, fixture_paths)?;

    for run in runs {
        on_summary(&run.summary);
        handle_success_mismatch(&run.summary, &run.path, cli.allow_success_mismatch)?;
    }

    Ok(())
}

fn run_fixtures(
    guest: GuestKind,
    jobs: usize,
    fixture_paths: Vec<PathBuf>,
) -> anyhow::Result<Vec<FixtureRun>> {
    if jobs == 1 || fixture_paths.len() <= 1 {
        return fixture_paths
            .iter()
            .map(|fixture_path| run_fixture_path(guest, fixture_path))
            .collect();
    }

    let pool = ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("failed to create fixture worker pool")?;

    pool.install(|| {
        fixture_paths
            .par_iter()
            .map(|fixture_path| run_fixture_path(guest, fixture_path))
            .collect()
    })
}

fn run_fixture_path(guest: GuestKind, fixture_path: &Path) -> anyhow::Result<FixtureRun> {
    let fixture = load_fixture(fixture_path)?;
    let summary = guest
        .run_fixture(&fixture)
        .with_context(|| format!("failed to execute fixture {}", fixture_path.display()))?;

    Ok(FixtureRun {
        path: fixture_path.to_path_buf(),
        summary,
    })
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .try_init();
}

fn handle_success_mismatch(
    summary: &RunSummary,
    fixture_path: &Path,
    allow_success_mismatch: bool,
) -> anyhow::Result<()> {
    if summary.actual_success == summary.expected_success {
        return Ok(());
    }

    if allow_success_mismatch {
        tracing::warn!(
            fixture_name = summary.fixture_name.as_str(),
            fixture_path = %fixture_path.display(),
            expected_success = summary.expected_success,
            actual_success = summary.actual_success,
            "fixture success mismatch",
        );
        return Ok(());
    }

    bail!(
        "fixture {} ({}) expected success={}, got success={}",
        summary.fixture_name,
        fixture_path.display(),
        summary.expected_success,
        summary.actual_success,
    );
}

/// Collects fixture file paths from a JSON file or a directory.
pub fn collect_fixture_paths(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            bail!(
                "fixture file {} must have a .json extension",
                path.display()
            );
        }
        return Ok(vec![path.to_path_buf()]);
    }

    if !path.exists() {
        bail!("path {} does not exist", path.display());
    }

    if !path.is_dir() {
        bail!("path {} must be a file or directory", path.display());
    }

    let mut paths = fs::read_dir(path)
        .with_context(|| format!("failed to read fixture directory {}", path.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let entry_path = entry.path();
            let file_type = entry.file_type().ok()?;
            (file_type.is_file()
                && entry_path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .then_some(entry_path)
        })
        .collect::<Vec<_>>();
    paths.sort();

    if paths.is_empty() {
        bail!("no JSON fixtures found in {}", path.display());
    }

    Ok(paths)
}

/// Loads one JSON fixture from disk.
pub fn load_fixture(path: &Path) -> anyhow::Result<StatelessValidatorFixture> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read fixture {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to deserialize fixture {}", path.display()))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
