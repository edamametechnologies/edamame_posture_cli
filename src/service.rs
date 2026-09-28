//! Native service integration for every distribution channel.
//!
//! `install-service` registers edamame_posture with the OS service manager
//! (a LaunchDaemon on macOS, a Windows service, a systemd unit for raw Linux
//! binaries), `uninstall-service` removes it, and `service-run` is the entry
//! point the service manager starts. The PKG, Homebrew, Chocolatey and raw
//! binaries all use the same subcommands; the Linux APT/APK packages keep
//! their own systemd unit / OpenRC script (`edamame_posture_daemon.sh`).
//!
//! Configuration is the Linux conf format (`linux/edamame_posture.conf`), read
//! by `service-run` itself from a file only root / SYSTEM / Administrators can
//! read. Secrets (PIN, LLM and notification keys) therefore never appear on a
//! command line or in the service definition: the LaunchDaemon plist, the
//! systemd unit and the Windows service command line only carry
//! `service-run --conf <path>`.

use clap::{Arg, ArgAction, ArgMatches, Command};
use std::io::Write;
use std::path::{Path, PathBuf};

const SERVICE_RUN: &str = "service-run";
const INSTALL_SERVICE: &str = "install-service";
const UNINSTALL_SERVICE: &str = "uninstall-service";

/// launchd label (macOS).
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.edamametechnologies.edamame-posture";
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.edamametechnologies.edamame-posture.plist";
/// Holds the conf path of an installed service. `brew upgrade` runs the
/// cask's uninstall (which removes the plist) before installing the new PKG;
/// the PKG postinstall re-runs install-service when this marker exists.
#[cfg(target_os = "macos")]
const SERVICE_MARKER: &str = "/Library/Application Support/EDAMAME/EDAMAME-Posture/service-enabled";

/// Windows service name, also the systemd unit name on Linux.
#[cfg(any(target_os = "windows", target_os = "linux"))]
const SERVICE_NAME: &str = "edamame_posture";

/// The template written when no configuration exists yet.
const CONF_TEMPLATE: &str = include_str!("../linux/edamame_posture.conf");

pub fn service_subcommands() -> Vec<Command> {
    let conf_arg = || {
        Arg::new("conf")
            .long("conf")
            .value_name("PATH")
            .help(format!(
                "Configuration file (default: {})",
                default_conf_path().display()
            ))
            .value_parser(clap::value_parser!(PathBuf))
    };
    vec![
        Command::new(SERVICE_RUN)
            .about("Run as the native service (started by launchd, the Windows SCM or systemd); reads its configuration from --conf")
            .arg(conf_arg()),
        Command::new(INSTALL_SERVICE)
            .about("Install and start edamame_posture as a native service (LaunchDaemon on macOS, Windows service, systemd unit for raw Linux binaries); requires admin privileges")
            .arg(conf_arg())
            .arg(
                Arg::new("no_start")
                    .long("no-start")
                    .help("Register the service without starting it now (it starts at the next boot)")
                    .action(ArgAction::SetTrue),
            ),
        Command::new(UNINSTALL_SERVICE)
            .about("Stop and remove the native service installed by install-service; requires admin privileges")
            .arg(conf_arg())
            .arg(
                Arg::new("purge")
                    .long("purge")
                    .help("Also delete the configuration file")
                    .action(ArgAction::SetTrue),
            ),
    ]
}

pub fn is_service_command(name: &str) -> bool {
    matches!(name, SERVICE_RUN | INSTALL_SERVICE | UNINSTALL_SERVICE)
}

/// Dispatches the service subcommands; returns the process exit code
/// (`service-run` only returns on a configuration error).
pub fn run_command(name: &str, matches: &ArgMatches, verbose: bool) -> i32 {
    let conf = matches
        .get_one::<PathBuf>("conf")
        .cloned()
        .unwrap_or_else(default_conf_path);
    // service-run changes directory, and the service definition must not
    // depend on the directory install-service ran from.
    let conf = std::path::absolute(&conf).unwrap_or(conf);
    let result = match name {
        SERVICE_RUN => return service_run(conf, verbose),
        INSTALL_SERVICE => install_service(&conf, matches.get_flag("no_start")),
        UNINSTALL_SERVICE => uninstall_service(&conf, matches.get_flag("purge")),
        _ => Err(format!("unknown service command {}", name)),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}", e);
            crate::ERROR_CODE_PARAM
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Paths
////////////////////////////////////////////////////////////////////////////////

#[cfg(target_os = "windows")]
fn program_data_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()))
        .join("EDAMAME")
        .join("Posture")
}

pub fn default_conf_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.conf")
    }
    #[cfg(target_os = "windows")]
    {
        program_data_dir().join("edamame_posture.conf")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/etc/edamame_posture.conf")
    }
}

/// The service's working directory. Never `/`: in CI mode the file monitor
/// falls back to the current directory as a recursive watch root (see
/// debian/edamame_posture.service).
fn state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/EDAMAME/EDAMAME-Posture")
    }
    #[cfg(target_os = "windows")]
    {
        program_data_dir()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/edamame_posture")
    }
}

/// Errors before the core's logger exists (bad configuration, service
/// registration) go to stderr and to this file, the only place a service
/// start failure is visible on Windows.
fn service_log(message: &str) {
    eprintln!("{}", message);
    let path = state_dir().join("edamame_posture_service.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{}] {}", secs, message);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Configuration
////////////////////////////////////////////////////////////////////////////////

/// Reads `key` from a conf in the Linux format. Same rules as
/// `get_config_value` in linux/edamame_posture_daemon.sh: the first line
/// starting with `key:` wins; a double-quoted value is read up to its closing
/// quote with backslash escapes, a single-quoted one up to the next quote, and
/// an unquoted one loses a trailing ` # comment`.
pub(crate) fn conf_value(text: &str, key: &str) -> String {
    let prefix = format!("{}:", key);
    for raw in text.lines() {
        let line = raw.trim_start_matches([' ', '\t']);
        if !line.starts_with(&prefix) {
            continue;
        }
        let v = line[prefix.len()..].trim_start_matches([' ', '\t']);
        if let Some(rest) = v.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some(n) => out.push(n),
                        None => out.push(c),
                    }
                    continue;
                }
                if c == '"' {
                    break;
                }
                out.push(c);
            }
            return out;
        }
        if let Some(rest) = v.strip_prefix('\'') {
            return match rest.find('\'') {
                Some(p) => rest[..p].to_string(),
                None => rest.to_string(),
            };
        }
        // Unquoted: drop the first "<blank>+#..." and trailing blanks.
        let bytes = v.as_bytes();
        let mut cut = v.len();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b' ' || bytes[i] == b'\t' {
                let mut j = i;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'#' {
                    cut = i;
                    break;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        return v[..cut].trim_end_matches([' ', '\t']).to_string();
    }
    String::new()
}

/// What `service-run` starts, resolved from the conf the same way the Linux
/// wrapper resolves it.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ServiceConfig {
    pub user: String,
    pub domain: String,
    pub pin: String,
    pub device_id: String,
    pub network_scan: bool,
    pub packet_capture: bool,
    pub whitelist: String,
    pub fail_on_whitelist: bool,
    pub fail_on_blacklist: bool,
    pub fail_on_findings: bool,
    pub cancel_on_violation: bool,
    pub include_local_traffic: bool,
    pub agentic_mode: String,
    pub agentic_provider: Option<String>,
    pub agentic_interval: u64,
    pub llm_api_key: Option<String>,
    /// Environment exported to the core before start (LLM and notification
    /// settings the core reads from the environment).
    pub env: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

fn is_true(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("true")
}

fn first_non_empty(values: &[&str]) -> String {
    values
        .iter()
        .find(|v| !v.is_empty())
        .map(|v| v.to_string())
        .unwrap_or_default()
}

impl ServiceConfig {
    /// `pin_env` is `EDAMAME_PIN` from the service environment, the last
    /// fallback after `edamame_pin` and `edamame_pin_file` in the conf.
    #[cfg(test)]
    pub(crate) fn from_conf(text: &str, pin_env: Option<String>) -> Result<Self, String> {
        Self::from_conf_with_env(text, pin_env, None)
    }

    /// As [`Self::from_conf`], plus `token_env`: `EDAMAME_ENROLLMENT_TOKEN`
    /// from the service environment, the fallback after
    /// `edamame_enrollment_token` and `edamame_enrollment_token_file`. With
    /// no PIN, a user, a domain and a token start in connected mode: the
    /// daemon enrolls the device in the Hub with the token (MDM deployment).
    pub(crate) fn from_conf_with_env(
        text: &str,
        pin_env: Option<String>,
        token_env: Option<String>,
    ) -> Result<Self, String> {
        let get = |k: &str| conf_value(text, k);
        let mut cfg = ServiceConfig::default();

        cfg.user = get("edamame_user");
        cfg.domain = get("edamame_domain");
        cfg.device_id = get("edamame_device_id");
        let mut pin = get("edamame_pin");
        if pin.is_empty() {
            let pin_file = get("edamame_pin_file");
            if !pin_file.is_empty() {
                pin = std::fs::read_to_string(&pin_file)
                    .map_err(|e| format!("Cannot read edamame_pin_file {}: {}", pin_file, e))?
                    .trim()
                    .to_string();
            }
        }
        if pin.is_empty() {
            pin = pin_env.unwrap_or_default().trim().to_string();
        }
        let mut token = get("edamame_enrollment_token");
        if token.is_empty() {
            let token_file = get("edamame_enrollment_token_file");
            if !token_file.is_empty() {
                token = std::fs::read_to_string(&token_file)
                    .map_err(|e| {
                        format!(
                            "Cannot read edamame_enrollment_token_file {}: {}",
                            token_file, e
                        )
                    })?
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        }
        if token.is_empty() {
            token = token_env.unwrap_or_default().trim().to_string();
        }
        if !cfg.user.is_empty() && !cfg.domain.is_empty() && (!pin.is_empty() || !token.is_empty())
        {
            crate::parse_username(&cfg.user).map_err(|e| format!("edamame_user: {}", e))?;
            crate::parse_fqdn(&cfg.domain).map_err(|e| format!("edamame_domain: {}", e))?;
            if !pin.is_empty() {
                crate::parse_digits_only(&pin).map_err(|e| format!("edamame_pin: {}", e))?;
                cfg.pin = pin;
            } else {
                // Handed to the daemon through its environment, read once
                // and removed there (never argv, never a log line).
                cfg.env
                    .push((crate::cli::ENROLLMENT_TOKEN_ENV.to_string(), token));
            }
        } else {
            // Disconnected mode, as in the Linux wrapper.
            cfg.user.clear();
            cfg.domain.clear();
            cfg.device_id.clear();
        }

        cfg.network_scan = is_true(&get("start_lanscan"));
        cfg.packet_capture = is_true(&get("start_capture"));
        cfg.whitelist = get("whitelist_name");
        cfg.fail_on_whitelist = is_true(&get("fail_on_whitelist")) || !cfg.whitelist.is_empty();
        cfg.fail_on_blacklist = is_true(&get("fail_on_blacklist"));
        cfg.fail_on_findings = is_true(&get("fail_on_findings"));
        cfg.cancel_on_violation = is_true(&get("cancel_on_violation"));
        cfg.include_local_traffic = is_true(&get("include_local_traffic"));

        let mode = get("agentic_mode").to_lowercase();
        let mode = if mode.is_empty() {
            "disabled".to_string()
        } else {
            mode
        };
        if !matches!(mode.as_str(), "auto" | "analyze" | "disabled") {
            return Err(format!(
                "agentic_mode '{}' is not one of auto, analyze, disabled",
                mode
            ));
        }
        let interval = get("agentic_interval");
        cfg.agentic_interval = if interval.is_empty() {
            3600
        } else {
            interval.parse().map_err(|_| {
                format!("agentic_interval '{}' is not a number of seconds", interval)
            })?
        };

        // LLM provider: same resolution as the Linux wrapper. A provider
        // named in the conf decides which credential slot is authoritative;
        // otherwise the first non-empty slot wins.
        let llm_api_key = get("llm_api_key");
        let claude_api_key = get("claude_api_key");
        let openai_api_key = get("openai_api_key");
        // llm_model / llm_base_url: optional model and API base URL for any
        // provider; llm_base_url doubles as the Ollama URL.
        let llm_model = get("llm_model");
        let llm_base_url = get("llm_base_url");
        let ollama_base_url = first_non_empty(&[&get("ollama_base_url"), &llm_base_url]);
        let configured = get("agentic_provider").to_lowercase();
        let pick = |p: &str| -> Option<(String, String, &'static str)> {
            match p {
                "edamame" if !llm_api_key.is_empty() => {
                    Some(("edamame".into(), llm_api_key.clone(), "EDAMAME_LLM_API_KEY"))
                }
                "claude" if !claude_api_key.is_empty() => Some((
                    "claude".into(),
                    claude_api_key.clone(),
                    "EDAMAME_LLM_API_KEY",
                )),
                "openai" if !openai_api_key.is_empty() => Some((
                    "openai".into(),
                    openai_api_key.clone(),
                    "EDAMAME_LLM_API_KEY",
                )),
                "ollama" if !ollama_base_url.is_empty() => Some((
                    "ollama".into(),
                    ollama_base_url.clone(),
                    "EDAMAME_LLM_BASE_URL",
                )),
                _ => None,
            }
        };
        let chosen = if configured.is_empty() {
            ["edamame", "claude", "openai", "ollama"]
                .iter()
                .find_map(|p| pick(p))
        } else {
            pick(&configured)
        };
        match chosen {
            Some((provider, value, var)) => {
                if var == "EDAMAME_LLM_API_KEY" {
                    cfg.llm_api_key = Some(value.clone());
                }
                cfg.env.push((var.to_string(), value));
                if provider != "ollama" && !llm_base_url.is_empty() {
                    cfg.env
                        .push(("EDAMAME_LLM_BASE_URL".to_string(), llm_base_url.clone()));
                }
                if !llm_model.is_empty() {
                    cfg.env
                        .push(("EDAMAME_LLM_MODEL".to_string(), llm_model.clone()));
                }
                cfg.agentic_provider = Some(provider);
            }
            None => {
                if mode != "disabled" {
                    cfg.warnings.push(if configured.is_empty() {
                        format!("agentic_mode is '{}' but no LLM credential is set; the AI assistant stays disabled", mode)
                    } else {
                        format!("agentic_provider is '{}' but its credential slot is empty; the AI assistant stays disabled", configured)
                    });
                }
            }
        }
        // The wrapper only passes --agentic-* when a provider resolved.
        cfg.agentic_mode = if cfg.agentic_provider.is_some() {
            mode
        } else {
            "disabled".to_string()
        };
        if cfg.agentic_mode == "disabled" {
            cfg.agentic_provider = None;
        }

        // Notifications (unified keys win over the legacy ones).
        let provider = get("notification_provider").to_lowercase();
        let mut slack_token = first_non_empty(&[
            &get("notification_slack_bot_token"),
            &get("slack_bot_token"),
        ]);
        let slack_channel = get("notification_slack_channel");
        let mut slack_actions = first_non_empty(&[&get("slack_actions_channel"), &slack_channel]);
        let mut slack_escalations = first_non_empty(&[
            &get("slack_escalations_channel"),
            &slack_channel,
            &slack_actions,
        ]);
        let mut telegram_token = first_non_empty(&[
            &get("notification_telegram_bot_token"),
            &get("telegram_bot_token"),
        ]);
        let mut telegram_chat = first_non_empty(&[
            &get("notification_telegram_chat_id"),
            &get("telegram_chat_id"),
        ]);
        match provider.as_str() {
            "" | "auto" | "both" => {}
            "slack" => {
                telegram_token.clear();
                telegram_chat.clear();
            }
            "telegram" => {
                slack_token.clear();
                slack_actions.clear();
                slack_escalations.clear();
            }
            other => cfg.warnings.push(format!(
                "Unknown notification_provider '{}', using auto",
                other
            )),
        }
        if !slack_token.is_empty() {
            cfg.env.push((
                "EDAMAME_AGENTIC_SLACK_BOT_TOKEN".into(),
                slack_token.clone(),
            ));
            cfg.env
                .push(("EDAMAME_AGENTIC_WEBHOOK_ACTIONS_TOKEN".into(), slack_token));
        }
        if !slack_actions.is_empty() {
            cfg.env.push((
                "EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL".into(),
                slack_actions.clone(),
            ));
            cfg.env.push((
                "EDAMAME_AGENTIC_WEBHOOK_ACTIONS_CHANNEL".into(),
                slack_actions,
            ));
        }
        if !slack_escalations.is_empty() {
            cfg.env.push((
                "EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL".into(),
                slack_escalations.clone(),
            ));
            cfg.env.push((
                "EDAMAME_AGENTIC_WEBHOOK_ESCALATIONS_CHANNEL".into(),
                slack_escalations,
            ));
        }
        if !telegram_token.is_empty() && !telegram_chat.is_empty() {
            cfg.env
                .push(("EDAMAME_TELEGRAM_BOT_TOKEN".into(), telegram_token));
            cfg.env
                .push(("EDAMAME_TELEGRAM_CHAT_ID".into(), telegram_chat));
        }

        Ok(cfg)
    }

    fn apply_env(&self) {
        for (k, v) in &self.env {
            std::env::set_var(k, v);
        }
    }

    /// Starts the daemon in this process. Only returns if the daemon loop
    /// ends, which it does not in service mode.
    fn run(self, verbose: bool) {
        self.apply_env();
        crate::run_background(
            self.user,
            self.domain,
            self.pin,
            self.device_id,
            self.network_scan,
            self.packet_capture,
            self.whitelist,
            self.fail_on_whitelist,
            self.fail_on_blacklist,
            self.fail_on_findings,
            self.cancel_on_violation,
            self.include_local_traffic,
            verbose,
            self.agentic_mode,
            self.agentic_provider,
            self.agentic_interval,
            self.llm_api_key,
        );
    }
}

/// The conf holds secrets and decides what a root/SYSTEM process runs: on
/// Unix it must be owned by root and writable by root only. Returns warnings
/// for a conf other users can read.
#[cfg(unix)]
fn check_conf_permissions(path: &Path) -> Result<Vec<String>, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    if meta.uid() != 0 {
        return Err(format!(
            "{} must be owned by root (sudo chown root {} && sudo chmod 600 {})",
            path.display(),
            path.display(),
            path.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by users other than root (sudo chmod 600 {})",
            path.display(),
            path.display()
        ));
    }
    let mut warnings = Vec::new();
    if meta.mode() & 0o044 != 0 {
        warnings.push(format!(
            "{} is readable by other users and may hold secrets (sudo chmod 600 {})",
            path.display(),
            path.display()
        ));
    }
    Ok(warnings)
}

/// Windows: install-service sets the SYSTEM/Administrators-only ACL.
#[cfg(not(unix))]
fn check_conf_permissions(_path: &Path) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

fn load_config(conf: &Path) -> Result<ServiceConfig, String> {
    let perm_warnings = check_conf_permissions(conf)?;
    let text = std::fs::read_to_string(conf)
        .map_err(|e| format!("Cannot read {}: {}", conf.display(), e))?;
    let mut cfg = ServiceConfig::from_conf_with_env(
        &text,
        std::env::var("EDAMAME_PIN").ok(),
        std::env::var(crate::cli::ENROLLMENT_TOKEN_ENV).ok(),
    )
    .map_err(|e| format!("{}: {}", conf.display(), e))?;
    cfg.warnings.extend(perm_warnings);
    Ok(cfg)
}

////////////////////////////////////////////////////////////////////////////////
// service-run
////////////////////////////////////////////////////////////////////////////////

fn enter_state_dir() {
    let dir = state_dir();
    if std::fs::create_dir_all(&dir).is_ok() && std::env::set_current_dir(&dir).is_ok() {
        return;
    }
    let _ = std::env::set_current_dir(std::env::temp_dir());
}

fn service_run(conf: PathBuf, verbose: bool) -> i32 {
    enter_state_dir();

    #[cfg(target_os = "windows")]
    {
        match windows_service_host::run(conf.clone(), verbose) {
            Ok(true) => return 0,
            Ok(false) => {} // Not started by the SCM: run in this console.
            Err(e) => {
                service_log(&format!("Windows service dispatcher failed: {}", e));
                return crate::ERROR_CODE_SERVER_ERROR;
            }
        }
    }

    match load_config(&conf) {
        Ok(cfg) => {
            for w in &cfg.warnings {
                service_log(&format!("WARNING: {}", w));
            }
            cfg.run(verbose);
            0
        }
        Err(e) => {
            service_log(&format!("edamame_posture service not started: {}", e));
            crate::ERROR_CODE_PARAM
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_service_host {
    use super::{load_config, service_log, SERVICE_NAME};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};

    /// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: the process was not started
    /// by the SCM.
    const NOT_A_SERVICE: i32 = 1063;

    static CONTEXT: OnceLock<(PathBuf, bool)> = OnceLock::new();
    static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Ok(true) once the service has run, Ok(false) when this process is not
    /// a service.
    pub fn run(conf: PathBuf, verbose: bool) -> Result<bool, String> {
        let _ = CONTEXT.set((conf, verbose));
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(true),
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
                Ok(false)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn set_status(state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration) {
        if let Some(handle) = STATUS.get() {
            let controls_accepted = if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            };
            let _ = handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted,
                exit_code,
                checkpoint: 0,
                wait_hint,
                process_id: None,
            });
        }
    }

    /// Stop / shutdown: report STOPPED before exiting, otherwise the SCM
    /// counts the exit as a failure and applies the restart actions.
    fn stop() {
        set_status(
            ServiceState::StopPending,
            ServiceExitCode::Win32(0),
            Duration::from_secs(30),
        );
        if edamame_foundation::runtime::is_initialized() {
            edamame_core::api::api_core::terminate(false);
        }
        set_status(
            ServiceState::Stopped,
            ServiceExitCode::Win32(0),
            Duration::default(),
        );
        std::process::exit(0);
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (conf, verbose) = match CONTEXT.get() {
            Some(c) => c.clone(),
            None => return,
        };
        let handler = move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    std::thread::spawn(stop);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let handle = match service_control_handler::register(SERVICE_NAME, handler) {
            Ok(h) => h,
            Err(e) => {
                service_log(&format!(
                    "Cannot register the service control handler: {}",
                    e
                ));
                return;
            }
        };
        let _ = STATUS.set(handle);

        // A broken conf is a failed start, visible in `sc query`.
        let cfg = match load_config(&conf) {
            Ok(cfg) => cfg,
            Err(e) => {
                service_log(&format!("edamame_posture service not started: {}", e));
                set_status(
                    ServiceState::Stopped,
                    ServiceExitCode::ServiceSpecific(crate::ERROR_CODE_PARAM as u32),
                    Duration::default(),
                );
                return;
            }
        };
        for w in &cfg.warnings {
            service_log(&format!("WARNING: {}", w));
        }
        set_status(
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::default(),
        );
        cfg.run(verbose);
        set_status(
            ServiceState::Stopped,
            ServiceExitCode::Win32(0),
            Duration::default(),
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// install-service / uninstall-service
////////////////////////////////////////////////////////////////////////////////

#[cfg(unix)]
fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("This command requires root privileges (run it with sudo)".to_string());
    }
    Ok(())
}

/// A service runs this binary as root: refuse one that a non-root user could
/// replace (the binary or any directory above it writable by others).
#[cfg(unix)]
fn check_root_owned_chain(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(path);
    while let Some(p) = current {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {}", p.display(), e))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "Refusing to register {} as a root service: {} is not owned by root or is writable by other users. Install edamame_posture to a root-owned location first (the PKG, Homebrew, or /usr/local/bin).",
                path.display(),
                p.display()
            ));
        }
        current = p.parent();
    }
    Ok(())
}

fn current_exe() -> Result<PathBuf, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("Cannot locate edamame_posture: {}", e))?;
    // Resolve /usr/local/bin/edamame_posture -> the PKG's app bundle, whose
    // embedded provisioning profile carries the Endpoint Security entitlement.
    std::fs::canonicalize(&exe).map_err(|e| format!("{}: {}", exe.display(), e))
}

/// Creates the conf from the template when missing and restricts it to root.
#[cfg(unix)]
fn ensure_conf(conf: &Path) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(dir) = conf.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    if !conf.exists() {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(conf)
            .map_err(|e| format!("{}: {}", conf.display(), e))?;
        f.write_all(CONF_TEMPLATE.as_bytes())
            .map_err(|e| format!("{}: {}", conf.display(), e))?;
        println!("Wrote the configuration template {}", conf.display());
    }
    std::os::unix::fs::chown(conf, Some(0), Some(0))
        .map_err(|e| format!("chown {}: {}", conf.display(), e))?;
    std::fs::set_permissions(conf, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {}", conf.display(), e))?;
    Ok(())
}

#[cfg(unix)]
fn run_tool(program: &str, args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("{}: {}", program, e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} failed ({})",
            program,
            args.join(" "),
            status
        ))
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The LaunchDaemon definition (no secrets: the conf path only).
#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) fn launchd_plist(label: &str, exe: &Path, conf: &Path, workdir: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>service-run</string>
    <string>--conf</string>
    <string>{conf}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>WorkingDirectory</key>
  <string>{workdir}</string>
  <key>StandardOutPath</key>
  <string>/var/log/edamame_posture_service.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/edamame_posture_service.log</string>
</dict>
</plist>
"#,
        label = xml_escape(label),
        exe = xml_escape(&exe.to_string_lossy()),
        conf = xml_escape(&conf.to_string_lossy()),
        workdir = xml_escape(&workdir.to_string_lossy()),
    )
}

/// The systemd unit for raw Linux binaries (the APT package ships its own).
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(crate) fn systemd_unit(exe: &Path, conf: &Path) -> String {
    format!(
        r#"# Written by `edamame_posture install-service`; remove with `edamame_posture uninstall-service`.
[Unit]
Description=EDAMAME Security posture analysis and remediation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="{exe}" service-run --conf "{conf}"
StateDirectory=edamame_posture
WorkingDirectory=/var/lib/edamame_posture
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
"#,
        exe = exe.display(),
        conf = conf.display()
    )
}

#[cfg(target_os = "macos")]
fn install_service(conf: &Path, no_start: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    require_root()?;
    let exe = current_exe()?;
    check_root_owned_chain(&exe)?;
    ensure_conf(conf)?;
    let workdir = state_dir();
    std::fs::create_dir_all(&workdir).map_err(|e| format!("{}: {}", workdir.display(), e))?;

    let target = format!("system/{}", LAUNCHD_LABEL);
    // Re-install / upgrade: unload the previous definition first.
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &target])
        .stderr(std::process::Stdio::null())
        .status();

    let plist = launchd_plist(LAUNCHD_LABEL, &exe, conf, &workdir);
    std::fs::write(LAUNCHD_PLIST, plist).map_err(|e| format!("{}: {}", LAUNCHD_PLIST, e))?;
    std::os::unix::fs::chown(LAUNCHD_PLIST, Some(0), Some(0))
        .map_err(|e| format!("chown {}: {}", LAUNCHD_PLIST, e))?;
    std::fs::set_permissions(LAUNCHD_PLIST, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("chmod {}: {}", LAUNCHD_PLIST, e))?;
    println!("Wrote {}", LAUNCHD_PLIST);
    std::fs::write(SERVICE_MARKER, format!("{}\n", conf.display()))
        .map_err(|e| format!("{}: {}", SERVICE_MARKER, e))?;

    if no_start {
        println!(
            "The service starts at the next boot (or: sudo launchctl bootstrap system {}).",
            LAUNCHD_PLIST
        );
        return Ok(());
    }
    run_tool("/bin/launchctl", &["bootstrap", "system", LAUNCHD_PLIST])?;
    let _ = run_tool("/bin/launchctl", &["enable", &target]);
    println!(
        "Service {} started. Configuration: {} (after a change: sudo launchctl kickstart -k {}).",
        LAUNCHD_LABEL,
        conf.display(),
        target
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service(conf: &Path, purge: bool) -> Result<(), String> {
    require_root()?;
    let target = format!("system/{}", LAUNCHD_LABEL);
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &target])
        .stderr(std::process::Stdio::null())
        .status();
    if Path::new(LAUNCHD_PLIST).exists() {
        std::fs::remove_file(LAUNCHD_PLIST).map_err(|e| format!("{}: {}", LAUNCHD_PLIST, e))?;
    }
    let _ = std::fs::remove_file(SERVICE_MARKER);
    println!("Service {} removed.", LAUNCHD_LABEL);
    purge_conf(conf, purge)
}

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/edamame_posture.service";

#[cfg(target_os = "linux")]
fn packaged_unit_present() -> bool {
    [
        "/lib/systemd/system/edamame_posture.service",
        "/usr/lib/systemd/system/edamame_posture.service",
        "/etc/init.d/edamame_posture",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

#[cfg(target_os = "linux")]
fn install_service(conf: &Path, no_start: bool) -> Result<(), String> {
    require_root()?;
    if packaged_unit_present() {
        return Err(format!(
            "The edamame-posture package already provides the {} service. Edit {} and restart it (systemctl restart {} / rc-service {} restart).",
            SERVICE_NAME,
            default_conf_path().display(),
            SERVICE_NAME,
            SERVICE_NAME
        ));
    }
    if !Path::new("/run/systemd/system").exists() {
        return Err("systemd is not running on this host; install the edamame-posture APT/APK package instead".to_string());
    }
    let exe = current_exe()?;
    check_root_owned_chain(&exe)?;
    ensure_conf(conf)?;
    std::fs::write(SYSTEMD_UNIT_PATH, systemd_unit(&exe, conf))
        .map_err(|e| format!("{}: {}", SYSTEMD_UNIT_PATH, e))?;
    println!("Wrote {}", SYSTEMD_UNIT_PATH);
    run_tool("systemctl", &["daemon-reload"])?;
    if no_start {
        run_tool("systemctl", &["enable", SERVICE_NAME])?;
    } else {
        run_tool("systemctl", &["enable", "--now", SERVICE_NAME])?;
        // Pick up a new binary / conf when re-installed over a running unit.
        run_tool("systemctl", &["restart", SERVICE_NAME])?;
    }
    println!(
        "Service {} installed. Configuration: {} (after a change: systemctl restart {}).",
        SERVICE_NAME,
        conf.display(),
        SERVICE_NAME
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service(conf: &Path, purge: bool) -> Result<(), String> {
    require_root()?;
    if !Path::new(SYSTEMD_UNIT_PATH).exists() {
        if packaged_unit_present() {
            return Err(
                "The service belongs to the edamame-posture package; remove the package instead"
                    .to_string(),
            );
        }
        println!("No service installed by install-service.");
        return purge_conf(conf, purge);
    }
    let _ = run_tool("systemctl", &["disable", "--now", SERVICE_NAME]);
    std::fs::remove_file(SYSTEMD_UNIT_PATH).map_err(|e| format!("{}: {}", SYSTEMD_UNIT_PATH, e))?;
    let _ = run_tool("systemctl", &["daemon-reload"]);
    println!("Service {} removed.", SERVICE_NAME);
    purge_conf(conf, purge)
}

#[cfg(target_os = "windows")]
mod windows_install {
    use super::{current_exe, state_dir, CONF_TEMPLATE, SERVICE_NAME};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    const DISPLAY_NAME: &str = "EDAMAME Posture";
    const DESCRIPTION: &str = "EDAMAME Security posture analysis and remediation";

    /// SYSTEM and Administrators only, not inherited from %ProgramData%
    /// (where Users can read and create files).
    fn restrict_acl(path: &Path, is_dir: bool) -> Result<(), String> {
        let grant = if is_dir { "(OI)(CI)F" } else { "F" };
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("*S-1-5-18:{}", grant))
            .arg(format!("*S-1-5-32-544:{}", grant))
            .stdout(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("icacls: {}", e))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("icacls {} failed ({})", path.display(), status))
        }
    }

    fn ensure_conf(conf: &Path) -> Result<(), String> {
        let dir = state_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        restrict_acl(&dir, true)?;
        if let Some(parent) = conf.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {}", parent.display(), e))?;
        }
        if !conf.exists() {
            std::fs::write(conf, CONF_TEMPLATE.replace('\n', "\r\n"))
                .map_err(|e| format!("{}: {}", conf.display(), e))?;
            println!("Wrote the configuration template {}", conf.display());
        }
        restrict_acl(conf, false)
    }

    /// The service binary lives in %ProgramFiles% (Administrators-only), not
    /// wherever this copy was downloaded to.
    fn service_exe_path() -> PathBuf {
        PathBuf::from(
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()),
        )
        .join("EDAMAME")
        .join("Posture")
        .join("edamame_posture.exe")
    }

    fn manager() -> Result<ServiceManager, String> {
        ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| {
            format!(
                "Cannot open the service manager (run as Administrator): {}",
                e
            )
        })
    }

    fn stop_and_wait(service: &windows_service::service::Service) {
        if let Ok(status) = service.query_status() {
            if status.current_state != ServiceState::Stopped {
                let _ = service.stop();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            match service.query_status() {
                Ok(s) if s.current_state == ServiceState::Stopped => return,
                Err(_) => return,
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    pub fn install(conf: &Path, no_start: bool) -> Result<(), String> {
        let manager = manager()?;
        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;
        let existing = manager.open_service(SERVICE_NAME, access).ok();
        if let Some(service) = &existing {
            stop_and_wait(service);
        }

        ensure_conf(conf)?;

        let source = current_exe()?;
        let target = service_exe_path();
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        }
        let same = std::fs::canonicalize(&target)
            .map(|t| t == source)
            .unwrap_or(false);
        if !same {
            std::fs::copy(&source, &target).map_err(|e| {
                format!(
                    "Cannot copy {} to {}: {}",
                    source.display(),
                    target.display(),
                    e
                )
            })?;
            println!("Installed {}", target.display());
        }

        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: target.clone(),
            launch_arguments: vec![
                OsString::from("service-run"),
                OsString::from("--conf"),
                conf.as_os_str().to_os_string(),
            ],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = match existing {
            Some(service) => {
                service
                    .change_config(&info)
                    .map_err(|e| format!("Cannot update the {} service: {}", SERVICE_NAME, e))?;
                service
            }
            None => manager
                .create_service(&info, access)
                .map_err(|e| format!("Cannot create the {} service: {}", SERVICE_NAME, e))?,
        };
        let _ = service.set_description(DESCRIPTION);
        // Restart after a crash or a non-zero exit, like systemd Restart=always.
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![restart(5), restart(30), restart(60)]),
            })
            .map_err(|e| format!("Cannot set the restart policy: {}", e))?;
        let _ = service.set_failure_actions_on_non_crash_failures(true);

        if no_start {
            println!(
                "Service {} registered (starts at the next boot).",
                SERVICE_NAME
            );
            return Ok(());
        }
        service
            .start::<OsString>(&[])
            .map_err(|e| format!("Cannot start the {} service: {}", SERVICE_NAME, e))?;
        println!(
            "Service {} started. Configuration: {} (after a change: Restart-Service {}).",
            SERVICE_NAME,
            conf.display(),
            SERVICE_NAME
        );
        Ok(())
    }

    pub fn uninstall() -> Result<(), String> {
        let manager = manager()?;
        match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            Ok(service) => {
                stop_and_wait(&service);
                service
                    .delete()
                    .map_err(|e| format!("Cannot delete the {} service: {}", SERVICE_NAME, e))?;
                println!("Service {} removed.", SERVICE_NAME);
            }
            Err(_) => println!("No {} service installed.", SERVICE_NAME),
        }
        let target = service_exe_path();
        let running_from_target = current_exe().map(|e| e == target).unwrap_or(false);
        if !running_from_target && target.exists() {
            let _ = std::fs::remove_file(&target);
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn install_service(conf: &Path, no_start: bool) -> Result<(), String> {
    windows_install::install(conf, no_start)
}

#[cfg(target_os = "windows")]
fn uninstall_service(conf: &Path, purge: bool) -> Result<(), String> {
    windows_install::uninstall()?;
    purge_conf(conf, purge)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn install_service(_conf: &Path, _no_start: bool) -> Result<(), String> {
    Err("install-service is not supported on this platform".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn uninstall_service(_conf: &Path, _purge: bool) -> Result<(), String> {
    Err("uninstall-service is not supported on this platform".to_string())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn purge_conf(conf: &Path, purge: bool) -> Result<(), String> {
    if purge && conf.exists() {
        std::fs::remove_file(conf).map_err(|e| format!("{}: {}", conf.display(), e))?;
        println!("Removed {}", conf.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_value_matches_the_linux_wrapper_parser() {
        let text = "\
# comment
  edamame_user: \"alice\"
edamame_domain: example.com   # trailing comment
edamame_pin: '123456'
edamame_pin_file: \"\"
quoted: \"a \\\"b\\\" c # not a comment\"
hash_in_value: a#b
crlf: \"x\"\r
edamame_user: \"bob\"
";
        assert_eq!(conf_value(text, "edamame_user"), "alice");
        assert_eq!(conf_value(text, "edamame_domain"), "example.com");
        assert_eq!(conf_value(text, "edamame_pin"), "123456");
        assert_eq!(conf_value(text, "edamame_pin_file"), "");
        assert_eq!(conf_value(text, "quoted"), "a \"b\" c # not a comment");
        assert_eq!(conf_value(text, "hash_in_value"), "a#b");
        assert_eq!(conf_value(text, "crlf"), "x");
        assert_eq!(conf_value(text, "missing"), "");
    }

    #[test]
    fn packaged_template_starts_disconnected_and_disabled() {
        let cfg = ServiceConfig::from_conf(CONF_TEMPLATE, None).unwrap();
        assert_eq!(cfg.user, "");
        assert_eq!(cfg.pin, "");
        assert_eq!(cfg.agentic_mode, "disabled");
        assert_eq!(cfg.agentic_provider, None);
        assert_eq!(cfg.agentic_interval, 3600);
        assert!(!cfg.network_scan && !cfg.packet_capture);
        assert!(cfg.env.is_empty());
    }

    #[test]
    fn connected_mode_needs_user_domain_and_pin() {
        let text = "edamame_user: \"alice\"\nedamame_domain: \"example.com\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        assert_eq!(cfg.user, "", "no PIN: disconnected");
        let cfg = ServiceConfig::from_conf(text, Some("123456".into())).unwrap();
        assert_eq!(
            (cfg.user.as_str(), cfg.domain.as_str(), cfg.pin.as_str()),
            ("alice", "example.com", "123456")
        );
    }

    #[test]
    fn enrollment_token_starts_connected_without_a_pin() {
        const TOKEN: &str = "edm_enr_0123456789abcdef0123456789abcdef_secretpart";
        let base = "edamame_user: \"alice\"\nedamame_domain: \"example.com\"\n";
        let token_env = |cfg: &ServiceConfig| {
            cfg.env
                .iter()
                .find(|(k, _)| k == crate::cli::ENROLLMENT_TOKEN_ENV)
                .map(|(_, v)| v.clone())
        };

        // Conf key.
        let text = format!("{base}edamame_enrollment_token: \"{TOKEN}\"\n");
        let cfg = ServiceConfig::from_conf_with_env(&text, None, None).unwrap();
        assert_eq!((cfg.user.as_str(), cfg.pin.as_str()), ("alice", ""));
        assert_eq!(token_env(&cfg).as_deref(), Some(TOKEN));

        // Service environment fallback.
        let cfg = ServiceConfig::from_conf_with_env(base, None, Some(TOKEN.into())).unwrap();
        assert_eq!(cfg.user, "alice");
        assert_eq!(token_env(&cfg).as_deref(), Some(TOKEN));

        // Token file.
        let dir = std::env::temp_dir().join(format!("posture-svc-enroll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
        let text = format!(
            "{base}edamame_enrollment_token_file: \"{}\"\n",
            file.display()
        );
        let cfg = ServiceConfig::from_conf_with_env(&text, None, None).unwrap();
        assert_eq!(token_env(&cfg).as_deref(), Some(TOKEN));
        let _ = std::fs::remove_dir_all(&dir);

        // A PIN wins: the token is not handed over.
        let text =
            format!("{base}edamame_pin: \"123456\"\nedamame_enrollment_token: \"{TOKEN}\"\n");
        let cfg = ServiceConfig::from_conf_with_env(&text, None, None).unwrap();
        assert_eq!(cfg.pin, "123456");
        assert_eq!(token_env(&cfg), None);

        // No user: disconnected, token ignored.
        let cfg = ServiceConfig::from_conf_with_env("", None, Some(TOKEN.into())).unwrap();
        assert_eq!(cfg.user, "");
        assert_eq!(token_env(&cfg), None);
    }

    #[test]
    fn pin_file_is_read_and_conf_pin_wins() {
        let dir = std::env::temp_dir().join(format!("edamame_posture_pin_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pin_file = dir.join("pin");
        std::fs::write(&pin_file, "654321\n").unwrap();
        let base = format!(
            "edamame_user: \"alice\"\nedamame_domain: \"example.com\"\nedamame_pin_file: \"{}\"\n",
            pin_file.display()
        );
        let cfg = ServiceConfig::from_conf(&base, Some("111111".into())).unwrap();
        assert_eq!(cfg.pin, "654321");
        let with_pin = format!("{}edamame_pin: \"123456\"\n", base);
        assert_eq!(
            ServiceConfig::from_conf(&with_pin, None).unwrap().pin,
            "123456"
        );
        let missing = base.replace(&pin_file.display().to_string(), "/nonexistent/pin");
        assert!(ServiceConfig::from_conf(&missing, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_pin_is_rejected() {
        let text =
            "edamame_user: \"alice\"\nedamame_domain: \"example.com\"\nedamame_pin: \"12ab\"\n";
        assert!(ServiceConfig::from_conf(text, None).is_err());
    }

    #[test]
    fn provider_resolution_matches_the_wrapper() {
        // First non-empty slot wins when no provider is named.
        let text =
            "agentic_mode: \"analyze\"\nclaude_api_key: \"sk-c\"\nopenai_api_key: \"sk-o\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        assert_eq!(cfg.agentic_mode, "analyze");
        assert_eq!(cfg.agentic_provider.as_deref(), Some("claude"));
        assert_eq!(cfg.llm_api_key.as_deref(), Some("sk-c"));
        assert!(cfg
            .env
            .contains(&("EDAMAME_LLM_API_KEY".to_string(), "sk-c".to_string())));

        // A named provider with an empty slot disables the assistant.
        let text =
            "agentic_mode: \"auto\"\nagentic_provider: \"edamame\"\nclaude_api_key: \"sk-c\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        assert_eq!(cfg.agentic_mode, "disabled");
        assert_eq!(cfg.agentic_provider, None);
        assert_eq!(cfg.warnings.len(), 1);

        // Ollama exports the base URL, not an API key.
        let text = "agentic_mode: \"analyze\"\nollama_base_url: \"http://localhost:11434\"\nagentic_interval: \"600\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        assert_eq!(cfg.agentic_provider.as_deref(), Some("ollama"));
        assert_eq!(cfg.llm_api_key, None);
        assert_eq!(cfg.agentic_interval, 600);
        assert!(cfg.env.contains(&(
            "EDAMAME_LLM_BASE_URL".to_string(),
            "http://localhost:11434".to_string()
        )));

        // llm_base_url is the Ollama URL too; llm_model is exported.
        let text = "agentic_mode: \"analyze\"\nagentic_provider: \"ollama\"\nllm_base_url: \"http://h:11434\"\nllm_model: \"llama3\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        assert_eq!(cfg.agentic_provider.as_deref(), Some("ollama"));
        assert!(cfg.env.contains(&(
            "EDAMAME_LLM_BASE_URL".to_string(),
            "http://h:11434".to_string()
        )));
        assert!(cfg
            .env
            .contains(&("EDAMAME_LLM_MODEL".to_string(), "llama3".to_string())));

        assert!(ServiceConfig::from_conf("agentic_mode: \"sometimes\"\n", None).is_err());
    }

    #[test]
    fn whitelist_implies_fail_on_whitelist() {
        let cfg = ServiceConfig::from_conf(
            "whitelist_name: \"github_ubuntu\"\nstart_capture: \"TRUE\"\n",
            None,
        )
        .unwrap();
        assert!(cfg.fail_on_whitelist);
        assert!(cfg.packet_capture);
    }

    #[test]
    fn notification_provider_filters_channels() {
        let text = "notification_provider: \"slack\"\nnotification_slack_bot_token: \"xoxb\"\nnotification_slack_channel: \"C1\"\ntelegram_bot_token: \"t\"\ntelegram_chat_id: \"1\"\n";
        let cfg = ServiceConfig::from_conf(text, None).unwrap();
        let keys: Vec<&str> = cfg.env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"EDAMAME_AGENTIC_SLACK_BOT_TOKEN"));
        assert!(keys.contains(&"EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL"));
        assert!(!keys.contains(&"EDAMAME_TELEGRAM_BOT_TOKEN"));
    }

    #[cfg(unix)]
    #[test]
    fn service_definitions_carry_no_secrets() {
        let exe = Path::new("/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.app/Contents/MacOS/edamame_posture");
        let conf =
            Path::new("/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.conf");
        let plist = launchd_plist(
            "com.edamametechnologies.edamame-posture",
            exe,
            conf,
            Path::new("/tmp"),
        );
        assert!(plist.contains("<string>service-run</string>"));
        assert!(!plist.to_lowercase().contains("pin"));
        let unit = systemd_unit(
            Path::new("/usr/local/bin/edamame_posture"),
            Path::new("/etc/edamame_posture.conf"),
        );
        assert!(unit.contains("ExecStart=\"/usr/local/bin/edamame_posture\" service-run --conf \"/etc/edamame_posture.conf\""));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_lints() {
        let exe = Path::new("/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.app/Contents/MacOS/edamame_posture");
        let conf = Path::new("/Library/Application Support/EDAMAME/EDAMAME-Posture/a&b.conf");
        let plist = launchd_plist(
            "com.edamametechnologies.edamame-posture",
            exe,
            conf,
            Path::new("/tmp"),
        );
        let path =
            std::env::temp_dir().join(format!("edamame_posture_test_{}.plist", std::process::id()));
        std::fs::write(&path, plist).unwrap();
        let out = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
