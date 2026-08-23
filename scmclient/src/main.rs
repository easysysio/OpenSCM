mod models;
mod agent;
mod config;
mod compliance;
mod runner;
mod containers;

// ─────────────────────────────────────────────────────────────────────────────
// Version stamp — machine-readable from the outside.
//
// The server bundles agent binaries for platforms it cannot execute (a Linux
// server serving a macOS or Windows agent), so it cannot ask a binary its
// version by running it. Nor can it recover the version from the ordinary
// compiled-in string: Rust packs literals into one .rodata blob with no null
// terminators and nothing tying the number to any nearby text.
//
// This static is a contiguous, self-describing byte string that a plain byte
// scan can find in any executable format — Mach-O, ELF or PE alike — with no
// format parsing at all. #[used] and #[no_mangle] keep the linker from
// discarding it: nothing in the program reads it.
//
// The server matches on the prefix and reads the version that follows, so the
// advertised upgrade version describes the payload instead of asserting it.
// ─────────────────────────────────────────────────────────────────────────────
#[used]
#[unsafe(no_mangle)]
pub static OPENSCM_AGENT_VERSION_TAG: &[u8] =
    concat!("<<OPENSCM_AGENT_VERSION:", env!("CARGO_PKG_VERSION"), ">>").as_bytes();

use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn, error};


use crate::config::{config_path,key_path};


fn check_required_directories() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Gather targets from your single-source-of-truth helpers
    let targets = [
        config_path(),
        key_path(),
    ];

    for target in targets {
        if let Some(parent) = std::path::Path::new(target).parent() {
            // Check if directory exists
            if !parent.exists() {
                info!("Required directory {:?} is missing. Attempting to create...", parent);
                
                // 2. Attempt to create. If it fails (e.g., Permission Denied), trigger the error logic.
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!(
                        "CRITICAL FAILURE: Could not create directory {:?}. Error: {}. \
                        This usually means the service lacks sufficient privileges or the \
                        installation is corrupt. Please reinstall the package or check permissions.", 
                        parent, e
                    );
                    return Err(format!("Missing required directory and failed to create: {:?}", parent).into());
                }
                info!("Successfully created directory: {:?}", parent);
            }

            // 3. Set secure permissions (Unix-specific)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let is_key_dir = target == key_path();
                let mode = if is_key_dir { 0o700 } else { 0o755 };

                if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode)) {
                    error!(
                        "CRITICAL FAILURE: Could not set permissions ({:o}) on {:?}. Error: {}. \
                        Ensure the OpenSCM service has ownership of its data directories.", 
                        mode, parent, e
                    );
                    return Err(format!("Permission hardening failed for: {:?}", parent).into());
                }
            }
        }
    }

    Ok(())
}


// The agent is a strictly sequential heartbeat loop (no tokio::spawn), so a
// single-threaded runtime is sufficient — and it avoids the multi-threaded
// runtime's per-worker glibc malloc arenas, which never return freed memory
// to the OS and made long-lived agents balloon to multi-GB RSS / 20-GB VSZ.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls is built without a default crypto provider (see Cargo.toml: the
    // aws-lc-rs default does not cross-compile to this project's targets), so
    // one must be installed before any TLS connection is attempted. Without
    // this every HTTPS request fails at runtime with "no process-level
    // CryptoProvider available".
    let _ = rustls::crypto::ring::default_provider().install_default();


    // 1. Logging setup
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    // 2. Version and CLI args
    let version = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = std::env::args().collect();

    for arg in &args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "-ver" | "--version" => {
                println!("OpenSCM Client version: {}", version);
                return Ok(());
            }
            _ => {}
        }
    }

    // 2a. `run` subcommand — local policy evaluation, no server interaction.
    //     Handled before config load / heartbeat loop because the runner is
    //     a one-shot tool and shouldn't block on missing config or network.
    if args.len() > 1 && args[1] == "run" {
        let mut policy_path: Option<String> = None;
        let mut format = runner::OutputFormat::Text;
        let mut strict = false;
        let mut failed_only = false;
        let mut cmd_enabled_override: Option<bool> = None;
        let mut ps_enabled_override:  Option<bool> = None;

        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--policy" if i + 1 < args.len() => { policy_path = Some(args[i + 1].clone()); i += 2; }
                "--format" if i + 1 < args.len() => {
                    format = match args[i + 1].to_lowercase().as_str() {
                        "json" => runner::OutputFormat::Json,
                        "text" => runner::OutputFormat::Text,
                        other  => {
                            eprintln!("Error: unknown --format '{}'. Use 'text' or 'json'.", other);
                            std::process::exit(2);
                        }
                    };
                    i += 2;
                }
                "--strict"       => { strict = true; i += 1; }
                "--failed-only"  => { failed_only = true; i += 1; }
                "--cmd-enabled"  => { cmd_enabled_override = Some(true); i += 1; }
                "--ps-enabled"   => { ps_enabled_override  = Some(true); i += 1; }
                "--no-cmd"       => { cmd_enabled_override = Some(false); i += 1; }
                "--no-ps"        => { ps_enabled_override  = Some(false); i += 1; }
                other => {
                    eprintln!("Error: unknown argument '{}' for 'run' subcommand.", other);
                    std::process::exit(2);
                }
            }
        }

        let policy_path = match policy_path {
            Some(p) => p,
            None => {
                eprintln!("Error: 'run' requires --policy <path>.");
                std::process::exit(2);
            }
        };

        // Default the gating flags to true in local mode — the user supplied
        // the policy file by hand at the CLI, so the "untrusted server pushing
        // arbitrary commands" threat model that gates the managed-agent mode
        // does not apply here. They can still pass --no-cmd / --no-ps to
        // explicitly opt out (e.g. in a sandbox / CI scan that must not exec).
        let cmd_enabled = cmd_enabled_override.unwrap_or(true);
        let ps_enabled  = ps_enabled_override.unwrap_or(true);

        let exit_code = runner::run(runner::RunOptions {
            policy_path, format, strict, failed_only, cmd_enabled, ps_enabled,
        });
        std::process::exit(exit_code as i32);
    }

	
    // 3. create required directories BEFORE logger init
    check_required_directories()?;

    // 3a. Single-instance guard (daemon mode only — the `run`/`--help`/
    //     `--version` one-shots returned above). Hold an exclusive advisory
    //     lock for the lifetime of the process so orphaned or duplicate agents
    //     can't pile up (the field symptom: dozens of stray scmclient daemons
    //     accumulating across self-upgrades). The self-upgrade exec()s the
    //     binary in place; Rust opens files O_CLOEXEC by default, so this lock
    //     is released across the exec and the re-exec'd image re-acquires it —
    //     no self-deadlock. Dropping `_instance_lock` (process exit) releases it.
    let _instance_lock = {
        use fs2::FileExt;
        use std::io::{Seek, SeekFrom, Write};
        let lock_path = config::lock_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true).read(true).write(true)
            .open(lock_path)
            .map_err(|e| { error!("Cannot open lock file {}: {}", lock_path, e); e })?;
        if file.try_lock_exclusive().is_err() {
            warn!("Another scmclient instance already holds {} — exiting to avoid \
                   duplicate agents.", lock_path);
            return Ok(());
        }
        // Record our PID in the lock file for operators (best-effort, cosmetic).
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(&file, "{}", std::process::id());
        file
    };

    // 4. Load config
    info!("Loading configuration...");
    let mut config = config::get_config().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    // 5. Handle URL override
    let mut config_changed = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            let new_url = args[i + 1].clone();
            info!("CLI Override: Setting Server URL to '{}'", new_url);
            config.server.url = new_url;
            config_changed = true;
            i += 2; // skip the value too
        } else {
            i += 1;
        }
    }

    if config_changed {
        config.save().map_err(|e| {
            error!("Failed to persist config: {}", e);
            e
        })?;
        info!("New configuration persisted.");
    }

    // 6. Startup info
    let server_url  = &config.server.url;
    let log_level   = config.client.loglevel.as_deref().unwrap_or("info");
    let heartbeat_secs = config.client.heartbeat
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);

    info!("================ OpenSCM Agent Configuration ================");
    info!("Server URL     : {}", server_url);
    info!("Client Version : {}", version);
    info!("Heartbeat      : {} seconds", heartbeat_secs);
    info!("Log Level      : {}", log_level);
    info!("=============================================================");

    if config.client.cmd_enabled.unwrap_or(false) {
        warn!("CMD element is ENABLED — this client will execute commands received from the server. Ensure you trust the server completely.");
    }

    // Apply log level from config
    let _ = reload_handle.reload(EnvFilter::new(log_level));

    // Track last applied log level to avoid redundant reloads
    let mut last_log_level = log_level.to_string();

    // Build the HTTP client once and reuse it for every heartbeat. reqwest's
    // connection pool only kicks in when the same Client instance is reused,
    // so building per-cycle was throwing away pooled connections and TLS
    // sessions every interval.
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| {
            error!("Failed to build HTTP client: {}", e);
            e
        })?;

    // 7. Main heartbeat loop
    loop {
        debug!("Starting heartbeat cycle");

        match agent::send_system_info(&mut config, &http_client).await {
            Ok(_)  => debug!("Heartbeat completed successfully"),
            Err(e) => warn!("Heartbeat failed: {}", e),
        }

        // Recalculate heartbeat interval in case config changed
        let current_heartbeat = config.client.heartbeat
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        // Only reload log level if it actually changed
        if let Some(level) = &config.client.loglevel {
            if *level != last_log_level {
                let _ = reload_handle.reload(EnvFilter::new(level));
                info!("Log level changed to '{}'", level);
                last_log_level = level.clone();
            }
        }

        // Apply jitter (0-9 seconds) to prevent thundering herd
        let jitter = rand::random::<u64>() % 10;
        let sleep_time = current_heartbeat + jitter;

        debug!("Next heartbeat in {} seconds", sleep_time);
        sleep(Duration::from_secs(sleep_time)).await;
    }
}

fn print_usage() {
    println!(r#"
OpenSCM Client - Security Compliance Manager Agent

USAGE:
    scmclient [OPTIONS]                            # Run as a managed agent (default)
    scmclient run --policy <FILE> [RUN OPTIONS]    # Local policy evaluation (no server)

OPTIONS:
    -h, --help          Print this help message
    -ver, --version     Print version information
    --url <URL>         Set or override the Server URL (e.g., http://localhost:8000)

RUN OPTIONS (for `scmclient run`):
    --policy <FILE>     Path to an OpenSCM policy JSON file (required)
    --format text|json  Output format (default: text)
    --strict            Exit with code 1 if any test fails
    --failed-only       Text mode: print only failing tests
    --no-cmd            Disable CMD elements (on by default in local mode)
    --no-ps             Disable PowerShell elements (on by default in local mode)

EXAMPLES:
    scmclient --url https://demo.openscm.io:8000
    scmclient run --policy cis-debian-13.json
    scmclient run --policy cis-debian-13.json --format json --strict
    scmclient run --policy custom.json --failed-only --cmd-enabled

EXIT CODES (for `scmclient run`):
    0   Success (or non-strict mode with failures)
    1   Strict mode and one or more tests failed
    2   Invalid arguments or policy file
    "#);
}
