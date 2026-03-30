use crate::{cache::Cache, config, crypto, shell, sync};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::collections::HashMap;
use std::io::{self, BufRead, Write as IoWrite};
use tracing::debug;

#[derive(Parser)]
#[command(
    name = "zenv",
    about = "Zero-config developer secret injection runtime",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Target environment
    #[arg(long, default_value = "development", global = true)]
    pub env: String,

    /// Enable verbose/debug output
    #[arg(long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new zenv project
    Init {
        /// Project name (defaults to directory name)
        #[arg(long)]
        name: Option<String>,
    },
    /// Run a command with injected secrets
    Run {
        /// Command to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Manage the encrypted secret vault
    #[command(subcommand)]
    Vault(VaultCommands),
    /// Shell integration
    #[command(subcommand)]
    Shell(ShellCommands),
    /// Sync secrets to external targets
    Sync {
        /// Target name (vercel, github, aws-sm)
        #[arg(long)]
        target: String,
        /// Show changes without pushing
        #[arg(long)]
        dry_run: bool,
    },
    /// Scan for leaked secrets in source files
    Scan {
        /// Path to scan (defaults to current directory)
        path: Option<String>,
    },
    /// Show project and device status
    Status,
    /// Device management
    #[command(subcommand)]
    Device(DeviceCommands),
}

#[derive(Subcommand)]
pub enum VaultCommands {
    /// Add or update a secret
    Add {
        /// Secret name (e.g., DATABASE_URL)
        name: String,
        /// Secret value (reads from stdin if omitted)
        value: Option<String>,
    },
    /// Get a secret value (raw, pipe-friendly)
    Get {
        /// Secret name
        name: String,
    },
    /// List all secrets
    List,
    /// Remove a secret
    Rm {
        /// Secret name
        name: String,
        /// Confirm deletion
        #[arg(long)]
        yes: bool,
    },
    /// Import secrets from a .env file
    Import {
        /// Path to .env file
        file: String,
        /// Overwrite existing secrets
        #[arg(long)]
        overwrite: bool,
    },
    /// Export secrets in .env format
    Export {
        /// Output file (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ShellCommands {
    /// Print the snippet to add to your shell RC file
    Install {
        /// Shell type
        #[arg(long)]
        shell: Option<String>,
    },
    /// Print the full hook script
    Hook {
        /// Shell type
        #[arg(long)]
        shell: Option<String>,
    },
    /// Print export statements for current secrets
    Export {
        /// Shell type
        #[arg(long)]
        shell: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DeviceCommands {
    /// Show device ID and key fingerprint
    Id,
    /// Print reset instructions (does NOT delete anything)
    Reset,
    /// Export master key for CI/CD use
    Export,
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("zenv=debug")
            .with_target(false)
            .init();
    }

    match cli.command {
        Commands::Init { name } => cmd_init(name).await,
        Commands::Run { command } => cmd_run(command, &cli.env).await,
        Commands::Vault(sub) => match sub {
            VaultCommands::Add { name, value } => cmd_vault_add(&name, value, &cli.env).await,
            VaultCommands::Get { name } => cmd_vault_get(&name).await,
            VaultCommands::List => cmd_vault_list(&cli.env).await,
            VaultCommands::Rm { name, yes } => cmd_vault_rm(&name, yes).await,
            VaultCommands::Import { file, overwrite } => {
                cmd_vault_import(&file, overwrite, &cli.env).await
            }
            VaultCommands::Export { output } => cmd_vault_export(output, &cli.env).await,
        },
        Commands::Shell(sub) => match sub {
            ShellCommands::Install { shell: sh } => cmd_shell_install(sh),
            ShellCommands::Hook { shell: sh } => cmd_shell_hook(sh),
            ShellCommands::Export { shell: sh } => cmd_shell_export(sh, &cli.env).await,
        },
        Commands::Sync { target, dry_run } => cmd_sync(&target, dry_run, &cli.env).await,
        Commands::Scan { path } => cmd_scan(path).await,
        Commands::Status => cmd_status(&cli.env).await,
        Commands::Device(sub) => match sub {
            DeviceCommands::Id => cmd_device_id().await,
            DeviceCommands::Reset => cmd_device_reset(),
            DeviceCommands::Export => cmd_device_export().await,
        },
    }
}

// ── Init ───────────────────────────────────────────────────────────

async fn cmd_init(name: Option<String>) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config_path = cwd.join(".zenv.toml");

    if config_path.exists() {
        println!(
            "{} project already initialized at {}",
            "⚠".yellow(),
            config_path.display().to_string().dimmed()
        );
        return Ok(());
    }

    let project_name = name.unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("untitled")
            .to_string()
    });

    // Initialize device config + master key
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;

    // Create project config
    let project = config::ProjectConfig::new(&project_name);
    project.save(&config_path)?;

    // Create empty cache
    let cache_dir = config::cache_dir()?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;
    cache.flush()?;

    // Append *.sealed to .gitignore if it exists
    let gitignore_path = cwd.join(".gitignore");
    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path)?;
        if !content.lines().any(|l| l.trim() == "*.sealed") {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&gitignore_path)?;
            writeln!(f, "\n# zenv encrypted cache\n*.sealed")?;
            println!(
                "  {} added {} to .gitignore",
                "→".dimmed(),
                "*.sealed".bold()
            );
        }
    }

    println!(
        "{} initialized project {}",
        "✓".green(),
        project_name.bold()
    );
    println!(
        "  {} project id: {}",
        "→".dimmed(),
        &project.project_id[..8].dimmed()
    );
    println!(
        "  {} device id:  {}",
        "→".dimmed(),
        &device.device_id[..8].dimmed()
    );
    println!();
    println!("Next steps:");
    println!(
        "  {} to add a secret",
        "zenv vault add DATABASE_URL".cyan()
    );
    println!(
        "  {} to import from .env",
        "zenv vault import .env".cyan()
    );
    println!(
        "  {} to run with secrets",
        "zenv run -- npm start".cyan()
    );

    Ok(())
}

// ── Run ────────────────────────────────────────────────────────────

async fn cmd_run(command: Vec<String>, environment: &str) -> anyhow::Result<()> {
    let start = std::time::Instant::now();

    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let secrets = cache.get_for_env(environment)?;

    // Build child environment
    let mut child_env: HashMap<String, String> = std::env::vars().collect();

    // Remove conflicting keys, then add ours
    for key in secrets.keys() {
        child_env.remove(key);
    }
    child_env.extend(secrets);
    child_env.insert("ZENV_ACTIVE".to_string(), "1".to_string());

    let overhead_ms = start.elapsed().as_millis();
    debug!("overhead_ms={}", overhead_ms);

    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    let program = &command[0];
    let args = &command[1..];

    // On Unix: exec() replaces the process — zero overhead after this point
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(program)
            .args(args)
            .envs(&child_env)
            .exec();
        // exec() only returns on error
        anyhow::bail!("exec failed: {}", err);
    }

    // On non-Unix: spawn + wait, propagate exit code
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(program)
            .args(args)
            .envs(&child_env)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

// ── Vault Add ──────────────────────────────────────────────────────

async fn cmd_vault_add(
    name: &str,
    value: Option<String>,
    environment: &str,
) -> anyhow::Result<()> {
    let value = match value {
        Some(v) => v,
        None => {
            eprint!("Enter value for {}: ", name.bold());
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            line.trim_end().to_string()
        }
    };

    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let mut cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let (is_secret, reason) = crypto::looks_like_secret(name, &value);
    if is_secret {
        debug!("detected secret type: {}", reason);
    }

    let existed = cache.set(name, &value, environment)?;
    cache.flush()?;

    if existed {
        println!(
            "{} updated {} in {}",
            "✓".green(),
            name.bold(),
            environment.green()
        );
    } else {
        println!(
            "{} vaulted {} in {}",
            "✓".green(),
            name.bold(),
            environment.green()
        );
    }

    Ok(())
}

// ── Vault Get ──────────────────────────────────────────────────────

async fn cmd_vault_get(name: &str) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let value = cache.get(name)?;
    // Print raw value, no newline (pipe-friendly)
    print!("{}", value);

    Ok(())
}

// ── Vault List ─────────────────────────────────────────────────────

async fn cmd_vault_list(environment: &str) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let metas = cache.list_meta();
    if metas.is_empty() {
        println!("No secrets stored. Run {} to add one.", "zenv vault add".cyan());
        return Ok(());
    }

    // Table header
    println!(
        "  {:<30} {:<15} {}",
        "NAME".bold(),
        "ENV".bold(),
        "UPDATED".bold()
    );
    println!("  {}", "─".repeat(65).dimmed());

    for meta in metas {
        let dynamic_tag = if meta.is_dynamic { " [dynamic]" } else { "" };
        let env_display = if meta.environment == environment || meta.environment == "all" {
            meta.environment.green().to_string()
        } else {
            meta.environment.dimmed().to_string()
        };
        println!(
            "  {:<30} {:<15} {}{}",
            meta.name.bold(),
            env_display,
            meta.updated_at.format("%Y-%m-%d %H:%M").to_string().dimmed(),
            dynamic_tag.dimmed()
        );
    }

    println!(
        "\n  {} secret(s) total",
        cache.count().to_string().bold()
    );

    Ok(())
}

// ── Vault Rm ───────────────────────────────────────────────────────

async fn cmd_vault_rm(name: &str, yes: bool) -> anyhow::Result<()> {
    if !yes {
        eprintln!(
            "{} use {} to confirm deletion of {}",
            "⚠".yellow(),
            "--yes".bold(),
            name.bold()
        );
        std::process::exit(1);
    }

    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let mut cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    cache.remove(name)?;
    cache.flush()?;

    println!("{} removed {}", "✓".green(), name.bold());

    Ok(())
}

// ── Vault Import ───────────────────────────────────────────────────

async fn cmd_vault_import(
    file: &str,
    overwrite: bool,
    environment: &str,
) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let mut cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let content = std::fs::read_to_string(file)?;
    let mut imported = 0;
    let mut skipped = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip `export ` prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        // Split on first `=`
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };

        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        // Handle quoted values
        let value = raw_value.trim();
        let value = if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };

        if cache.contains(key) && !overwrite {
            skipped += 1;
            debug!("skipping existing key: {}", key);
            continue;
        }

        cache.set(key, value, environment)?;
        imported += 1;
    }

    cache.flush()?;

    println!(
        "{} imported {} secret(s) from {}",
        "✓".green(),
        imported.to_string().bold(),
        file.dimmed()
    );
    if skipped > 0 {
        println!(
            "  {} skipped {} existing (use {} to overwrite)",
            "→".dimmed(),
            skipped,
            "--overwrite".bold()
        );
    }

    Ok(())
}

// ── Vault Export ───────────────────────────────────────────────────

async fn cmd_vault_export(
    output: Option<String>,
    environment: &str,
) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let secrets = cache.get_for_env(environment)?;
    let mut lines: Vec<String> = secrets
        .iter()
        .map(|(k, v)| {
            let escaped = v.replace('"', "\\\"");
            format!("{}=\"{}\"", k, escaped)
        })
        .collect();
    lines.sort();

    let content = lines.join("\n") + "\n";

    match output {
        Some(path) => {
            std::fs::write(&path, &content)?;
            println!(
                "{} exported {} secret(s) to {}",
                "✓".green(),
                secrets.len().to_string().bold(),
                path.dimmed()
            );
        }
        None => {
            print!("{}", content);
        }
    }

    Ok(())
}

// ── Shell Install ──────────────────────────────────────────────────

fn cmd_shell_install(shell_name: Option<String>) -> anyhow::Result<()> {
    let sh = shell_name
        .map(|s| shell::Shell::from_str_opt(&s))
        .unwrap_or_else(shell::Shell::detect);

    let snippet = shell::install_snippet(sh);
    println!("{}", snippet);

    eprintln!(
        "\n{} add the above to your {} config file",
        "→".dimmed(),
        sh.name().cyan()
    );

    Ok(())
}

// ── Shell Hook ─────────────────────────────────────────────────────

fn cmd_shell_hook(shell_name: Option<String>) -> anyhow::Result<()> {
    let sh = shell_name
        .map(|s| shell::Shell::from_str_opt(&s))
        .unwrap_or_else(shell::Shell::detect);

    println!("{}", shell::hook_script(sh));

    Ok(())
}

// ── Shell Export ───────────────────────────────────────────────────

async fn cmd_shell_export(
    shell_name: Option<String>,
    environment: &str,
) -> anyhow::Result<()> {
    let sh = shell_name
        .map(|s| shell::Shell::from_str_opt(&s))
        .unwrap_or_else(shell::Shell::detect);

    // Try to find project root; if not in a project, output nothing
    let root = match config::find_project_root() {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };

    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let secrets = cache.get_for_env(environment)?;
    if !secrets.is_empty() {
        println!("{}", shell::format_exports(&secrets, sh));
    }

    Ok(())
}

// ── Sync ───────────────────────────────────────────────────────────

async fn cmd_sync(
    target: &str,
    dry_run: bool,
    environment: &str,
) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    let local_secrets = cache.get_for_env(environment)?;

    // Compute diff against empty remote (fetching real remote requires configured credentials)
    let remote_secrets: HashMap<String, String> = HashMap::new();
    let diff = sync::compute_diff(&local_secrets, &remote_secrets);

    println!(
        "  {} sync to {} ({})",
        "→".dimmed(),
        target.bold(),
        environment.green()
    );
    println!();

    let mut adds = 0;
    let mut updates = 0;
    let mut removes = 0;
    let mut unchanged = 0;

    for entry in &diff {
        let (symbol, color_fn): (&str, Box<dyn Fn(&str) -> colored::ColoredString>) = match entry {
            sync::DiffEntry::Add { .. } => {
                adds += 1;
                ("+", Box::new(|s: &str| s.green()))
            }
            sync::DiffEntry::Update { .. } => {
                updates += 1;
                ("~", Box::new(|s: &str| s.yellow()))
            }
            sync::DiffEntry::Remove { .. } => {
                removes += 1;
                ("−", Box::new(|s: &str| s.red()))
            }
            sync::DiffEntry::Unchanged { .. } => {
                unchanged += 1;
                ("=", Box::new(|s: &str| s.dimmed()))
            }
        };
        println!("  {} {}", color_fn(symbol), color_fn(entry.key()));
    }

    println!();
    println!(
        "  {} add, {} update, {} remove, {} unchanged",
        adds.to_string().green(),
        updates.to_string().yellow(),
        removes.to_string().red(),
        unchanged.to_string().dimmed()
    );

    if dry_run {
        println!(
            "\n  {} dry run — no changes pushed",
            "→".dimmed()
        );
    } else {
        println!(
            "\n  {} to push changes, configure {} credentials in {}",
            "→".dimmed(),
            target.bold(),
            ".zenv.toml".cyan()
        );
        println!(
            "  {} see {} for sync target configuration",
            "→".dimmed(),
            "https://zenv.dev/docs/sync".cyan()
        );
    }

    Ok(())
}

// ── Scan ───────────────────────────────────────────────────────────

async fn cmd_scan(path: Option<String>) -> anyhow::Result<()> {
    let scan_root = path.unwrap_or_else(|| ".".to_string());
    let scan_path = std::path::Path::new(&scan_root);

    let skip_dirs = [
        "node_modules",
        "target",
        "dist",
        ".git",
        "vendor",
        "__pycache__",
        ".next",
        "build",
    ];
    let check_extensions = [
        "js", "ts", "jsx", "tsx", "py", "go", "rs", "rb", "sh", "env", "yaml", "yml", "json",
        "toml", "tf", "hcl",
    ];

    let mut findings = Vec::new();
    scan_directory(scan_path, &skip_dirs, &check_extensions, &mut findings)?;

    if findings.is_empty() {
        println!("{} no secrets detected", "✓".green());
    } else {
        println!(
            "{} found {} potential secret(s):\n",
            "⚠".yellow(),
            findings.len().to_string().bold()
        );
        for (file, line_num, key, reason) in &findings {
            println!(
                "  {}:{}",
                file.dimmed(),
                line_num.to_string().dimmed()
            );
            println!(
                "    {} {} — {}",
                "→".dimmed(),
                key.bold(),
                reason
            );
        }
    }

    Ok(())
}

fn scan_directory(
    dir: &std::path::Path,
    skip_dirs: &[&str],
    check_extensions: &[&str],
    findings: &mut Vec<(String, usize, String, &'static str)>,
) -> anyhow::Result<()> {
    if !dir.is_dir() {
        // Single file
        if let Some(ext) = dir.extension().and_then(|e| e.to_str()) {
            if check_extensions.contains(&ext) {
                scan_file(dir, findings)?;
            }
        }
        return Ok(());
    }

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            // Skip hidden dirs and known-large dirs
            if name_str.starts_with('.') || skip_dirs.contains(&name_str.as_ref()) {
                continue;
            }
            scan_directory(&path, skip_dirs, check_extensions, findings)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if check_extensions.contains(&ext) {
                scan_file(&path, findings)?;
            }
        }
    }

    Ok(())
}

fn scan_file(
    path: &std::path::Path,
    findings: &mut Vec<(String, usize, String, &'static str)>,
) -> anyhow::Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // Skip binary/unreadable files
    };

    let path_str = path.display().to_string();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        // Strip `export ` prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        // Try splitting on `=` (env files, shell, most langs)
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let key = lhs.trim().trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
            let val = rhs.trim().trim_matches(|c| c == '"' || c == '\'' || c == ';');

            if !key.is_empty() && !val.is_empty() {
                let (is_secret, reason) = crypto::looks_like_secret(key, val);
                if is_secret {
                    findings.push((path_str.clone(), line_num + 1, key.to_string(), reason));
                }
            }
        }

        // Try splitting on `:` (YAML)
        if let Some((lhs, rhs)) = trimmed.split_once(':') {
            let key = lhs.trim().trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
            let val = rhs.trim().trim_matches(|c| c == '"' || c == '\'' || c == ';');

            if !key.is_empty() && !val.is_empty() && val.len() > 8 {
                let (is_secret, reason) = crypto::looks_like_secret(key, val);
                if is_secret {
                    findings.push((path_str.clone(), line_num + 1, key.to_string(), reason));
                }
            }
        }
    }

    Ok(())
}

// ── Status ─────────────────────────────────────────────────────────

async fn cmd_status(environment: &str) -> anyhow::Result<()> {
    let root = config::find_project_root()?;
    let project = config::ProjectConfig::load(&root.join(".zenv.toml"))?;
    let device = config::DeviceConfig::load_or_create()?;

    let key_source = if std::env::var("ZENV_MASTER_KEY").is_ok() {
        "env var"
    } else {
        "keychain"
    };

    let master_key = crypto::load_or_create_master_key(&device.device_id)?;
    let storage_key = master_key.storage_key(&project.project_id);
    let cache_dir = config::cache_dir()?;
    let cache = Cache::open(&cache_dir, &project.project_id, storage_key)?;

    println!("  {:<16} {}", "project".bold(), project.project_name);
    println!(
        "  {:<16} {}",
        "project_id".bold(),
        &project.project_id[..8].dimmed()
    );
    println!(
        "  {:<16} {}",
        "device_id".bold(),
        &device.device_id[..8].dimmed()
    );
    println!(
        "  {:<16} {}",
        "environment".bold(),
        environment.green()
    );
    println!(
        "  {:<16} {}",
        "config".bold(),
        root.join(".zenv.toml").display().to_string().dimmed()
    );
    println!(
        "  {:<16} {}",
        "secrets".bold(),
        cache.count()
    );
    println!(
        "  {:<16} {}",
        "key storage".bold(),
        key_source
    );

    Ok(())
}

// ── Device ─────────────────────────────────────────────────────────

async fn cmd_device_id() -> anyhow::Result<()> {
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;

    println!("  {:<16} {}", "device_id".bold(), device.device_id);
    println!(
        "  {:<16} {}",
        "fingerprint".bold(),
        master_key.fingerprint()
    );
    println!(
        "  {:<16} {}",
        "created".bold(),
        device.created_at.format("%Y-%m-%d %H:%M UTC").to_string().dimmed()
    );

    Ok(())
}

fn cmd_device_reset() -> anyhow::Result<()> {
    println!("{} device reset is destructive", "⚠".yellow().bold());
    println!();
    println!("This will:");
    println!("  1. Delete your device key from the OS keychain");
    println!("  2. Remove ~/.zenv/device.toml");
    println!("  3. Make all locally cached secrets unreadable");
    println!();
    println!("To proceed manually:");
    println!(
        "  {} delete the keychain entry for \"zenv\"",
        "→".dimmed()
    );
    println!(
        "  {} {}",
        "→".dimmed(),
        "rm ~/.zenv/device.toml".cyan()
    );
    println!(
        "  {} {}",
        "→".dimmed(),
        "rm -rf ~/.zenv/cache/".cyan()
    );
    println!();
    println!(
        "After reset, run {} in each project to re-initialize.",
        "zenv init".cyan()
    );

    Ok(())
}

async fn cmd_device_export() -> anyhow::Result<()> {
    let device = config::DeviceConfig::load_or_create()?;
    let master_key = crypto::load_or_create_master_key(&device.device_id)?;

    println!(
        "{} this exports your master key in plaintext",
        "⚠".yellow().bold()
    );
    println!(
        "  {} use this only for CI/CD environments",
        "→".dimmed()
    );
    println!(
        "  {} store as a CI/CD secret, never in code",
        "→".dimmed()
    );
    println!();
    println!("ZENV_MASTER_KEY={}", hex::encode(&master_key.0));

    Ok(())
}
