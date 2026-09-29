use crate::background::background_display_sessions;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::{
    base_get_core_info, base_get_core_version, base_lanscan, connect_domain, ERROR_CODE_MISMATCH,
    ERROR_CODE_PARAM,
};
use edamame_core::api::api_core::*;
use edamame_core::api::api_flodbadd::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_trust::*;
use std::env;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, info, warn};

pub fn background_process(
    user: String,
    domain: String,
    pin: String,
    lan_scanning: bool,
    packet_capture: bool,
    whitelist_name: String,
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_findings: bool,
    cancel_on_violation: bool,
    local_traffic: bool,
    agentic_mode: String,
    agentic_provider: Option<String>,
    agentic_interval: u64,
) {
    let whitelist_display = if whitelist_name.is_empty() {
        "<none>"
    } else {
        whitelist_name.as_str()
    };

    info!(
        "Starting background process with user: {}, domain: {}, lan_scanning: {}, packet_capture: {}, whitelist: {}, fail_on_whitelist: {}, fail_on_blacklist: {}, fail_on_findings: {}, local_traffic: {}",
        user, domain, lan_scanning, packet_capture, whitelist_display, fail_on_whitelist, fail_on_blacklist, fail_on_findings, local_traffic
    );

    if fail_on_whitelist && whitelist_name.is_empty() {
        error!(
            "Whitelist fail handling requires a whitelist name. Provide --whitelist <NAME> when enabling --fail-on-whitelist."
        );
        crate::exit_process(ERROR_CODE_PARAM);
    }

    // Before anything starts: a mode the organization's lock refuses is an
    // error, never a daemon running without the loops it was asked for.
    exit_if_managed_policy_refuses(&agentic_mode);

    info!(
        "Live violation settings -> whitelist: {}, blacklist: {}, vulnerability_findings: {}, cancel_on_violation: {}",
        fail_on_whitelist, fail_on_blacklist, fail_on_findings, cancel_on_violation
    );

    // The live gate's scope: on a persistent runner this daemon and the
    // finding history outlive a job, and a finding first seen before the job
    // (or before this daemon) must not cancel it.
    let gate_since = crate::gate_scope::GateSince::for_this_daemon();
    if cancel_on_violation && fail_on_findings {
        info!(
            "Live attack pattern gate: counts findings first seen since {} ({}); older active findings are logged as warnings",
            gate_since.since.to_rfc3339(),
            gate_since.origin
        );
    }

    // We are using the logger as we are in the background process

    // Show threats info (call core directly to avoid local RPC chatter)
    let score = get_score(false, false);
    println!(
        "Threat model name: {}, date: {}, signature: {}",
        score.model_name, score.model_date, score.model_signature
    );

    // A Hub enrollment token (MDM deployment) handed over by the launcher,
    // the service conf or the environment: read once, then gone from the
    // environment so the daemon's children never inherit it.
    let enrollment_token = std::env::var(crate::cli::ENROLLMENT_TOKEN_ENV).unwrap_or_default();
    std::env::remove_var(crate::cli::ENROLLMENT_TOKEN_ENV);

    // Set credentials if not empty, otherwise the core will load saved credentials
    if user != "" && domain != "" {
        if pin.is_empty() && !enrollment_token.trim().is_empty() {
            // Enroll without the user's PIN; the core keeps the token and
            // then the device credential in the OS secret store. A device
            // already enrolled for this user reconnects without using it.
            info!(
                "Enrolling in the Hub with an enrollment token for user: {}, domain: {}",
                user, domain
            );
            let outcome = enroll_with_token(user.clone(), domain.clone(), enrollment_token);
            if !crate::enrollment_succeeded(&outcome) {
                error!("Hub enrollment did not complete: {}", outcome);
            }
        } else {
            info!("Setting credentials for user: {}, domain: {}", user, domain);
            set_credentials(user, domain, pin);
        }
    }

    // Initialize network to autodetect (this will allow the core to detect the network interfaces and support whitelist operations)
    set_network(NetworkAPI {
        interfaces: vec![],
        scanned_interfaces: vec![],
        is_ethernet: true,
        is_wifi: false,
        is_vpn: false,
        is_tethering: false,
        is_mobile: false,
        wifi_bssid: "".to_string(),
        wifi_ip: "".to_string(),
        wifi_submask: "".to_string(),
        wifi_gateway: "".to_string(),
        wifi_broadcast: "".to_string(),
        wifi_name: "".to_string(),
        wifi_ipv6: "".to_string(),
        // Must be in RFC3339 format, set to EPOCH
        last_seen: "1970-01-01T00:00:00Z".to_string(),
        last_name: "".to_string(),
    });

    // Force LAN auto-scan to follow the explicit start option, overriding any
    // previously persisted value from earlier runs.
    set_auto_scan(lan_scanning);

    if lan_scanning || packet_capture {
        // Grant consent when either capability is required
        grant_consent();
    }

    if packet_capture {
        if whitelist_name.is_empty() {
            info!("Packet capture enabled without whitelist enforcement.");
        } else {
            set_whitelist(whitelist_name.clone());
        }
        set_filter(if local_traffic {
            SessionFilterAPI::All
        } else {
            SessionFilterAPI::GlobalOnly
        });
        start_capture();
    } else {
        info!("Packet capture disabled. Skipping capture initialization.");
    }

    // Scan the network interfaces
    if lan_scanning {
        info!("Scanning network interfaces...");

        if packet_capture {
            // Wait for the gateway detection to complete
            let mut last_gateway_scan = get_last_gateway_scan();
            while last_gateway_scan.is_empty() {
                info!("Waiting for gateway detection to complete...");
                sleep(Duration::from_secs(5));
                last_gateway_scan = get_last_gateway_scan();
            }

            info!("Gateway detection complete, requesting a LAN scan...");
        } else {
            info!("Packet capture disabled; requesting LAN scan without waiting for gateway detection.");
        }

        // Request a LAN scan
        _ = get_lanscan(true, false, false);

        // Wait for the scan to complete
        base_lanscan();
    }

    info!("LAN scan complete, starting connection status loop");

    // Connect domain
    info!("Connecting to domain...");
    connect_domain();

    // Request a score computation
    compute_score();

    // Configure agentic AI only when the operator explicitly opted in. When
    // `agentic_mode == "disabled"` (the default in /etc/edamame_posture.conf, and
    // the default for `edamame_posture_action` jobs that don't pass --agentic-mode),
    // the daemon MUST NOT call background_set_agentic_loop(false, ...): calling
    // it on every daemon restart overwrites operator-set persisted state every
    // time the service restarts. (Core 2.0 keeps the Assistant and both
    // detection engines off until an operator turns them on; --agentic-mode
    // analyze|auto is that switch here and turns all three on together.)
    //
    // Mirror the EDAMAME app behavior: at startup, hydrate from persisted state
    // (already done in initialize_core via hydrate_agentic_from_persisted_config)
    // and only mutate agentic state when the operator explicitly opted in via
    // --agentic-mode <something other than "disabled">.
    //
    // `--agentic-mode off` is the explicit opposite: it turns agentic
    // protection off (the Assistant and both detection engines) through the
    // daemon's RPC, the same switch as the app's protection button.
    let agentic_enabled = agentic_mode != "disabled" && agentic_mode != "off";
    if agentic_mode == "off" {
        info!("AI Assistant mode 'off': turning agentic protection off");
        if !crate::background::background_turn_agentic_protection_off() {
            // A lock that appeared since the start-up check refuses the
            // same way.
            exit_if_managed_policy_refuses(&agentic_mode);
            warn!("Failed to turn agentic protection off");
        }
    } else if agentic_enabled {
        info!(
            "AI Assistant enabled: mode={}, provider={:?}, interval={}s",
            agentic_mode, agentic_provider, agentic_interval
        );

        if let Some(provider) = &agentic_provider {
            crate::background_configure_agentic(provider.clone());
        }

        if !crate::background_set_agentic_loop(agentic_enabled, agentic_interval, &agentic_mode) {
            // A lock that appeared since the start-up check refuses the
            // same way.
            exit_if_managed_policy_refuses(&agentic_mode);
            warn!("Failed to configure AI Assistant background loop");
        }

        // The operator asked for the LLM: the strict `llm` adjudication is
        // what a gate wants (G-46, fail closed when the model does not
        // answer), and the core's 2.0 default (`auto`) would run `advisory`
        // instead. Pin it unless a mode was already pinned explicitly; the
        // action's `adjudication_mode` input runs after start and overrides.
        crate::background::pin_llm_adjudication_when_auto();

        info!("AI Assistant: Processing security todos...");
        crate::background_process_agentic(&agentic_mode);
    } else {
        info!(
            "AI Assistant mode 'disabled': leaving persisted agentic state untouched (the Assistant, attack pattern detection and divergence detection remain as last set by the operator; all three are off on a fresh install)"
        );
    }

    // Loop forever as background process is running
    let mut violation_check_counter = 0u64;
    const VIOLATION_CHECK_INTERVAL: u64 = 10; // seconds (reduced from 30 for faster response)
    let mut live_gate = LiveGateState::default();
    loop {
        // Sleep for 5 seconds
        sleep(Duration::from_secs(5));
        violation_check_counter += 5;

        if cancel_on_violation && violation_check_counter >= VIOLATION_CHECK_INTERVAL {
            violation_check_counter = 0;
            match collect_policy_violations(
                fail_on_whitelist,
                fail_on_blacklist,
                fail_on_findings,
                local_traffic,
                &gate_since,
                &mut live_gate,
            ) {
                Ok(violations) => {
                    if let Some(refusal) = &violations.detector_refusal {
                        eprintln!("Error checking policy violations: {}", refusal);
                    }
                    if !violations.is_empty() {
                        if !violations.sessions.is_empty() {
                            println!("\n=== Violating Sessions Detected ===");
                            background_display_sessions(
                                violations.sessions,
                                false,
                                local_traffic,
                                false,
                            );
                        }
                        if violations.vulnerability_findings > 0 {
                            println!(
                                "\nActive vulnerability findings detected: {} ({})",
                                violations.vulnerability_findings, violations.vulnerability_label
                            );
                        }
                        println!("Live violations detected by background daemon. Attempting to cancel CI pipeline...");
                        let reason = if violations.vulnerability_findings > 0 {
                            "edamame_posture background daemon detected vulnerability findings"
                        } else {
                            "edamame_posture background daemon detected policy violations"
                        };
                        if let Err(e) = halt_ci_pipeline(reason) {
                            eprintln!("Failed to cancel pipeline: {}", e);
                        }
                        crate::exit_process(ERROR_CODE_MISMATCH);
                    }
                }
                Err(e) => {
                    eprintln!("Error checking policy violations: {}", e);
                }
            }
        }
    }
}

/// Exit non-zero, with the reason on stderr and in the log, when the
/// organization's locked protection policy refuses `--agentic-mode`
/// `agentic_mode`. The lock wins (decided 2026-09-29); before, the daemon
/// logged the refusal and ran on without the loops the operator asked for.
fn exit_if_managed_policy_refuses(agentic_mode: &str) {
    if let Some(refusal) = crate::background::agentic_mode_managed_refusal(agentic_mode) {
        error!("{}", refusal);
        eprintln!("{}", refusal);
        crate::exit_process(ERROR_CODE_PARAM);
    }
}

struct PolicyViolations {
    sessions: Vec<SessionInfoAPI>,
    vulnerability_findings: u64,
    vulnerability_label: String,
    /// Why the attack pattern detector's count certifies nothing this cycle
    /// (off, stalled, withheld past its budget, unreadable). Reported every
    /// cycle, never read as clean, and never hides the session violations
    /// found alongside it.
    detector_refusal: Option<String>,
}

impl PolicyViolations {
    fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.vulnerability_findings == 0
    }
}

fn collect_policy_violations(
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_findings: bool,
    include_local_traffic: bool,
    gate_since: &crate::gate_scope::GateSince,
    live_gate: &mut LiveGateState,
) -> Result<PolicyViolations, String> {
    let mut violating_sessions: Vec<SessionInfoAPI> = Vec::new();
    let mut vulnerability_findings = 0u64;
    let mut vulnerability_label = "HIGH/CRITICAL severity".to_string();

    if fail_on_whitelist {
        let conforms = rpc_get_whitelist_conformance(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        )
        .map_err(|e| format!("Error getting whitelist conformance: {}", e))?;

        if !conforms {
            let mut sessions = rpc_get_lan_sessions(
                true,
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            )
            .map_err(|e| format!("Error retrieving LAN sessions: {}", e))?
            .sessions;

            if !include_local_traffic {
                sessions = filter_global_sessions(sessions);
            }

            let non_conforming: Vec<SessionInfoAPI> = sessions
                .into_iter()
                .filter(|session| session.is_whitelisted != WhiteListStateAPI::Conforming)
                .collect();

            violating_sessions.extend(non_conforming);
        }
    }

    if fail_on_blacklist {
        let mut blacklisted = rpc_get_blacklisted_sessions(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        )
        .map_err(|e| format!("Error retrieving blacklisted sessions: {}", e))?;

        if !blacklisted.is_empty() {
            if !include_local_traffic {
                blacklisted = filter_global_sessions(blacklisted);
            }
            violating_sessions.extend(blacklisted);
        }
    }

    let mut detector_refusal = None;
    if fail_on_findings {
        match attack_pattern_findings_for_gate(gate_since, live_gate) {
            Ok((count, label)) => {
                vulnerability_findings = count;
                vulnerability_label = label;
            }
            Err(refusal) => detector_refusal = Some(refusal),
        }
    }

    Ok(PolicyViolations {
        sessions: violating_sessions,
        vulnerability_findings,
        vulnerability_label,
        detector_refusal,
    })
}

/// What the live gate keeps from one policy cycle to the next.
#[derive(Default)]
struct LiveGateState {
    /// Older findings already logged: each is reported once, not every cycle.
    reported_older: std::collections::HashSet<String>,
    /// The last split (how many findings count) and the detector status it was
    /// made from: the findings are listed again only once the counts or the
    /// last tick moved, not every 10 s while old findings stay active.
    last_split: Option<(String, u64)>,
}

/// Alertable attack pattern findings for the live gate, with the label to
/// print, or why the detector's count certifies nothing this cycle. Only
/// findings first seen since `gate_since` count; the older ones are logged
/// once each and never dismissed.
fn attack_pattern_findings_for_gate(
    gate_since: &crate::gate_scope::GateSince,
    live_gate: &mut LiveGateState,
) -> Result<(u64, String), String> {
    let status = edamame_core::api::api_agentic::get_attack_pattern_detector_status();
    let status_json: serde_json::Value = serde_json::from_str(&status)
        .map_err(|e| format!("Error parsing vulnerability detector status: {}", e))?;

    if let Some(error) = status_json.get("error").and_then(|value| value.as_str()) {
        return Err(format!(
            "Error getting vulnerability detector status: {}",
            error
        ));
    }

    // Liveness before counting: a detector that is off, or whose ticker
    // died (`running: true`, a frozen `last_run`), reports zero findings,
    // which reads exactly like a clean host. The gate cannot certify what
    // nobody observed, so fail closed.
    if let Some(refusal) = crate::background::attack_pattern_gate_refusal(&status_json) {
        return Err(refusal);
    }
    // G-46 (decided 2026-09-13): a withheld tick (LLM did not answer in
    // `llm` mode) is tolerated for one detector interval with a 120 s
    // floor, then fails the policy closed. This path runs on every policy
    // cycle, so the wait is a timestamp, not a sleep.
    if crate::background::adjudication_is_withheld(&status_json) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let since = match WITHHELD_SINCE_EPOCH.load(std::sync::atomic::Ordering::Relaxed) {
            0 => {
                WITHHELD_SINCE_EPOCH.store(now, std::sync::atomic::Ordering::Relaxed);
                now
            }
            since => since,
        };
        let budget_secs = status_json
            .get("interval_secs")
            .and_then(|value| value.as_u64())
            .unwrap_or(60)
            .max(120) as i64;
        if now - since > budget_secs {
            return Err(format!(
                "Attack pattern detector adjudication withheld for {}s (adjudication_status={}); its zero findings certify nothing",
                now - since,
                status_json
                    .get("adjudication_status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("?")
            ));
        }
    } else {
        WITHHELD_SINCE_EPOCH.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    let alertable = match status_json
        .get("active_alertable_findings")
        .and_then(|value| value.as_u64())
    {
        Some(alertable) => alertable,
        None => {
            return Ok((
                status_json
                    .get("active_findings")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0),
                "all severities (legacy daemon)".to_string(),
            ))
        }
    };
    if alertable == 0 {
        live_gate.last_split = None;
        return Ok((0, "HIGH/CRITICAL severity".to_string()));
    }

    // Split by first detection. Whatever cannot be told apart counts.
    let since_text = gate_since.since.to_rfc3339();
    let label = format!(
        "HIGH/CRITICAL severity, first seen since {} ({})",
        since_text, gate_since.origin
    );
    let split_key = format!(
        "{}|{}|{}",
        alertable,
        status_json
            .get("active_findings")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        status_json
            .get("last_run")
            .map(|v| v.to_string())
            .unwrap_or_default()
    );
    if let Some((key, current)) = &live_gate.last_split {
        if *key == split_key {
            return Ok((*current, label));
        }
    }
    let listing = edamame_core::api::api_agentic::get_attack_pattern_findings();
    let scoped = match crate::gate_scope::scope_findings(&listing, gate_since.since) {
        Some(scoped) if scoped.alertable() > 0 => scoped,
        _ => {
            warn!(
                "Live gate: the detector reports {} active HIGH/CRITICAL finding(s) the findings listing cannot date; every one counts",
                alertable
            );
            live_gate.last_split = None;
            return Ok((alertable, "HIGH/CRITICAL severity".to_string()));
        }
    };
    for older in &scoped.older {
        if live_gate.reported_older.insert(older.finding_key.clone()) {
            warn!(
                "Live gate: attack pattern finding from before {} ({}): {}. It does not cancel the pipeline and stays in the history until dismissed.",
                since_text,
                gate_since.origin,
                older.describe()
            );
        }
    }
    for current in &scoped.current {
        info!("Live gate: {}", current.describe());
    }
    let current = scoped.current.len() as u64;
    live_gate.last_split = Some((split_key, current));
    Ok((current, label))
}

/// Unix seconds of the first policy cycle that saw a withheld adjudication;
/// 0 when the latest tick was adjudicated or published. Lock-free on purpose:
/// the policy check must not be able to wedge on its own bookkeeping.
static WITHHELD_SINCE_EPOCH: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

fn halt_ci_pipeline(reason: &str) -> Result<(), String> {
    // Check for custom cancellation script first (most secure - no token passing to daemon)
    // The script is created by the CI action and has access to original environment including tokens
    let cancel_script_path = if let Ok(custom_path) = env::var("EDAMAME_CANCEL_PIPELINE_SCRIPT") {
        custom_path
    } else {
        // Default to $HOME/cancel_pipeline.sh
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/cancel_pipeline.sh", home)
    };

    // Try external script first if it exists
    if std::path::Path::new(&cancel_script_path).exists() {
        info!(
            "Using external cancellation script: {} (reason: {})",
            cancel_script_path, reason
        );

        let status = std::process::Command::new("bash")
            .arg(&cancel_script_path)
            .arg(reason)
            .status()
            .map_err(|e| format!("Failed to execute cancellation script: {}", e))?;

        if status.success() {
            info!("Pipeline cancelled successfully via script");
            return Ok(());
        } else {
            return Err(format!(
                "Cancellation script failed (exit code = {:?})",
                status.code()
            ));
        }
    }

    // Fallback to built-in cancellation logic
    info!(
        "No cancellation script found at {}, using built-in logic",
        cancel_script_path
    );

    if env::var("GITHUB_ACTIONS").is_ok() {
        let run_id = env::var("GITHUB_RUN_ID")
            .map_err(|_| "GITHUB_RUN_ID environment variable not set".to_string())?;
        let repo = env::var("GITHUB_REPOSITORY")
            .map_err(|_| "GITHUB_REPOSITORY environment variable not set".to_string())?;

        info!(
            "Attempting to cancel GitHub Actions run {} for repo {} (reason: {})",
            run_id, repo, reason
        );

        // Check for GitHub token from file first (more secure), then environment variable
        let gh_token = if let Ok(token_file) = env::var("GH_TOKEN_FILE") {
            match std::fs::read_to_string(&token_file) {
                Ok(token) => {
                    info!("Using GitHub token from secure file: {}", token_file);
                    Some(token.trim().to_string())
                }
                Err(e) => {
                    warn!("GH_TOKEN_FILE specified but couldn't read file: {}", e);
                    env::var("GH_TOKEN").ok()
                }
            }
        } else {
            env::var("GH_TOKEN").ok()
        };

        let mut cmd = std::process::Command::new("gh");
        cmd.args(["run", "cancel", &run_id, "--repo", &repo]);

        // Set GH_TOKEN environment variable for gh CLI if we found a token
        if let Some(token) = gh_token {
            cmd.env("GH_TOKEN", token);
        } else {
            warn!("No GitHub token found (GH_TOKEN_FILE or GH_TOKEN). Cancellation may fail if authentication is required.");
        }

        let status = cmd
            .status()
            .map_err(|e| format!("Failed to execute 'gh' command: {}", e))?;

        if status.success() {
            info!("GitHub Actions run cancelled successfully");
        } else {
            return Err(format!(
                "Failed to cancel GitHub Actions run (exit code = {:?})",
                status.code()
            ));
        }
    } else if env::var("GITLAB_CI").is_ok() {
        let project_id = env::var("CI_PROJECT_ID")
            .map_err(|_| "CI_PROJECT_ID environment variable not set".to_string())?;
        let pipeline_id = env::var("CI_PIPELINE_ID")
            .map_err(|_| "CI_PIPELINE_ID environment variable not set".to_string())?;
        let token = env::var("GITLAB_TOKEN")
            .map_err(|_| "GITLAB_TOKEN environment variable not set".to_string())?;

        info!(
            "Attempting to cancel GitLab pipeline {} for project {} (reason: {})",
            pipeline_id, project_id, reason
        );

        let url = format!(
            "https://gitlab.com/api/v4/projects/{}/pipelines/{}/cancel",
            project_id, pipeline_id
        );

        let status = std::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                &format!("PRIVATE-TOKEN: {}", token),
                &url,
            ])
            .status()
            .map_err(|e| format!("Failed to execute 'curl' command: {}", e))?;

        if status.success() {
            info!("GitLab pipeline cancelled successfully");
        } else {
            return Err(format!(
                "Failed to cancel GitLab pipeline (exit code = {:?})",
                status.code()
            ));
        }
    } else {
        info!(
            "Pipeline cancellation requested (reason: {}), but no supported CI environment detected.",
            reason
        );
    }

    Ok(())
}

pub fn is_background_process_running() -> bool {
    match rpc_get_core_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn background_start(
    user: String,
    domain: String,
    pin: String,
    device_id: String,
    lan_scanning: bool,
    packet_capture: bool,
    whitelist_name: String,
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_findings: bool,
    cancel_on_violation: bool,
    local_traffic: bool,
    agentic_mode: String,
    agentic_provider: Option<String>,
    agentic_interval: u64,
) {
    if fail_on_whitelist && whitelist_name.is_empty() {
        eprintln!(
            "Whitelist checks require a whitelist name. Provide --whitelist <NAME> when enabling --check-whitelist."
        );
        std::process::exit(ERROR_CODE_PARAM);
    }

    // The daemon would refuse the mode and exit once detached, where nobody
    // sees it: check the organization's lock here, so this command fails.
    exit_if_managed_policy_refuses(&agentic_mode);

    // Show core version
    base_get_core_version();

    // Show core info
    base_get_core_info();

    // Check if the background process is already running
    if is_background_process_running() {
        eprintln!("Core services are already running.");
        std::process::exit(1);
    }

    let whitelist_display = if whitelist_name.is_empty() {
        "<none>"
    } else {
        whitelist_name.as_str()
    };

    println!("Starting background process with provided parameters, user: {}, domain: {}, device_id: {}, lan_scanning: {}, packet_capture: {}, whitelist_name: {}, fail_on_whitelist: {}, fail_on_blacklist: {}, fail_on_findings: {}, cancel_on_violation: {}, local_traffic: {}, agentic_mode: {}, agentic_interval: {}s",
             user, domain, device_id, lan_scanning, packet_capture, whitelist_display, fail_on_whitelist, fail_on_blacklist, fail_on_findings, cancel_on_violation, local_traffic, agentic_mode, agentic_interval);

    #[cfg(unix)]
    {
        // The `background-process` arguments (the PIN slot stays, empty: the
        // PIN travels in the environment).
        let daemon_args = [
            user,
            domain,
            String::new(),
            device_id,
            lan_scanning.to_string(),
            packet_capture.to_string(),
            whitelist_name,
            fail_on_whitelist.to_string(),
            fail_on_blacklist.to_string(),
            fail_on_findings.to_string(),
            cancel_on_violation.to_string(),
            local_traffic.to_string(),
            agentic_mode,
            agentic_provider.unwrap_or_else(|| "none".to_string()),
            agentic_interval.to_string(),
        ];
        match spawn_daemon_supervisor(&pin, &daemon_args) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Error daemonizing: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(windows)]
    {
        use widestring::U16CString;
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::System::Threading::{
            CreateProcessW, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, PROCESS_INFORMATION,
            STARTF_USESTDHANDLES, STARTUPINFOW,
        };

        let exe = std::env::current_exe()
            .expect("Failed to get current executable path")
            .display()
            .to_string();
        // The PIN travels in the environment the child inherits
        // (CreateProcessW with no explicit block), not on its command line,
        // which any account can read and which is printed below. Always set,
        // so a disconnected start never inherits a caller's EDAMAME_PIN.
        std::env::set_var("EDAMAME_PIN", &pin);

        // Format the command line string, we must quote all strings
        // Must match the 17-arg format expected by background-process handler
        // (the PIN slot stays, empty)
        let cmd = format!(
            "\"{}\" background-process \"{}\" \"{}\" \"\" \"{}\" {} {} \"{}\" {} {} {} {} {} \"{}\" \"{}\" {}",
            exe,
            user,
            domain,
            device_id,
            lan_scanning.to_string(),
            packet_capture.to_string(),
            whitelist_name,
            fail_on_whitelist.to_string(),
            fail_on_blacklist.to_string(),
            fail_on_findings.to_string(),
            cancel_on_violation.to_string(),
            local_traffic.to_string(),
            agentic_mode,
            agentic_provider.as_deref().unwrap_or("none"),
            agentic_interval.to_string()
        );

        // Add CREATE_NEW_CONSOLE and CREATE_NO_WINDOW flags
        let creation_flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
        let mut process_information = PROCESS_INFORMATION::default();
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: INVALID_HANDLE_VALUE,
            hStdOutput: INVALID_HANDLE_VALUE,
            hStdError: INVALID_HANDLE_VALUE,
            ..Default::default()
        };

        println!("Command: {}", cmd);

        let mut cmd = U16CString::from_str(cmd).unwrap();
        let cmd_pwstr = PWSTR::from_raw(cmd.as_mut_ptr());

        match unsafe {
            CreateProcessW(
                PWSTR::null(),            // lpApplicationName
                cmd_pwstr,                // lpCommandLine
                None,                     // lpProcessAttributes
                None,                     // lpThreadAttributes
                false,                    // bInheritHandles
                creation_flags,           // dwCreationFlags
                None,                     // lpEnvironment
                PWSTR::null(),            // lpCurrentDirectory
                &startup_info,            // lpStartupInfo
                &mut process_information, // lpProcessInformation
            )
        } {
            Ok(_) => {
                println!(
                    "Background process ({}) launched",
                    process_information.dwProcessId
                );

                // In order to debug the launched process, uncomment this
                //unsafe { WaitForSingleObject(process_information.hProcess, INFINITE); }
                //let mut exit_code: u32 = 0;
                //unsafe { GetExitCodeProcess(process_information.hProcess, &mut exit_code); }
                //println!("exitcode: {}", exit_code);

                unsafe {
                    let _ = CloseHandle(process_information.hProcess);
                    let _ = CloseHandle(process_information.hThread);
                }
            }
            Err(e) => {
                eprintln!("Failed to create background process ({:?})", e);
                std::process::exit(1)
            }
        }
    }
}

/// Internal command line of the detached supervisor `background-start`
/// spawns on Unix: `edamame_posture background-supervisor <background-process
/// arguments>`. Read from the raw arguments like `background-process`, not a
/// clap subcommand.
#[cfg(unix)]
pub const DAEMON_SUPERVISOR_COMMAND: &str = "background-supervisor";
/// Created (mode 0640 under the umask below), locked and filled with its pid
/// by the supervisor, which holds the lock for its lifetime: a second
/// supervisor started meanwhile fails. Nothing reads it.
#[cfg(unix)]
const DAEMON_PID_FILE: &str = "/tmp/edamame_posture.pid";
#[cfg(unix)]
const DAEMON_WORKING_DIRECTORY: &str = "/tmp";
#[cfg(unix)]
const DAEMON_UMASK: libc::mode_t = 0o027;

/// Detach the daemon from the launcher: spawn the supervisor (see
/// [`detach`]) and do not wait for it: the launcher exits at once and the
/// supervisor is reparented.
///
/// Spawned, not forked: the launcher already runs the core's threads, and a
/// forked copy of a multi-threaded process may only make async-signal-safe
/// calls until it execs. The daemonize crate forked twice and then ran Rust
/// code (the pid file, `Command`) in the copy.
#[cfg(unix)]
fn spawn_daemon_supervisor(pin: &str, daemon_args: &[String]) -> std::io::Result<()> {
    let mut supervisor = std::process::Command::new(std::env::current_exe()?);
    supervisor
        .arg(DAEMON_SUPERVISOR_COMMAND)
        .args(daemon_args)
        // The PIN travels in the environment, not in argv (visible to every
        // account through ps); always set, so a disconnected start never
        // inherits a caller's EDAMAME_PIN.
        .env("EDAMAME_PIN", pin);
    detach(&mut supervisor);
    supervisor.spawn().map(|_| ())
}

/// Make `command` start detached: in a new session (`setsid` in the child,
/// before exec: a new session and process group, no controlling terminal), in
/// /tmp, with umask 027 and no standard input. Its stdout and stderr stay the
/// caller's: the supervisor moves them to /dev/null once it holds the pid
/// file lock, so a lock error still reaches whoever ran `background-start`.
#[cfg(unix)]
fn detach(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    command
        .current_dir(DAEMON_WORKING_DIRECTORY)
        .stdin(std::process::Stdio::null());
    // SAFETY: the closure runs between fork and exec, where only
    // async-signal-safe calls are allowed: setsid(2) and umask(2) are.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(DAEMON_UMASK);
            Ok(())
        });
    }
}

/// The supervisor `spawn_daemon_supervisor` starts: runs `background-process`
/// with `daemon_args` under [`supervise`]. Never returns.
#[cfg(unix)]
pub fn run_daemon_supervisor(daemon_args: &[String]) -> ! {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("Error daemonizing: {}", e);
            std::process::exit(1);
        }
    };
    let mut daemon = std::process::Command::new(exe);
    daemon.arg("background-process").args(daemon_args);
    std::process::exit(supervise(std::path::Path::new(DAEMON_PID_FILE), &mut daemon))
}

/// Take `pid_file`'s lock (a supervisor already holding it fails this one),
/// detach from the caller's standard streams, record this process's pid, then
/// run `daemon` and wait for it, so the daemon is reaped and the lock held
/// while it runs. Returns the supervisor's exit code: 0 once the daemon has
/// exited, whatever its status, 1 when it could not supervise.
#[cfg(unix)]
fn supervise(pid_file: &std::path::Path, daemon: &mut std::process::Command) -> i32 {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    // Opened close-on-exec (std's default): the daemon does not inherit the
    // descriptor, so the lock lives exactly as long as this process.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o666)
        .open(pid_file)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "Error daemonizing: unable to open pid file {}: {}",
                pid_file.display(),
                e
            );
            return 1;
        }
    };
    // SAFETY: flock on a descriptor this process owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        eprintln!(
            "Error daemonizing: unable to lock pid file {}: {}",
            pid_file.display(),
            std::io::Error::last_os_error()
        );
        return 1;
    }
    if let Err(e) = redirect_standard_streams_to_dev_null() {
        eprintln!(
            "Error daemonizing: unable to redirect the standard streams: {}",
            e
        );
        return 1;
    }
    if file
        .set_len(0)
        .and_then(|_| file.write_all(format!("{}\n", std::process::id()).as_bytes()))
        .is_err()
    {
        return 1;
    }

    // `output()`: wait for the daemon, whose stdout and stderr are pipes to
    // here and whose standard input is empty.
    match daemon.output() {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                eprintln!("Background process exited with status: {}", output.status);
                if !stderr.is_empty() {
                    eprintln!("stderr: {}", stderr);
                }
                if !stdout.is_empty() {
                    eprintln!("stdout: {}", stdout);
                }
            }
            drop(file);
            0
        }
        Err(e) => {
            eprintln!("Failed to start background process: {}", e);
            1
        }
    }
}

/// Point stdin, stdout and stderr at /dev/null.
#[cfg(unix)]
fn redirect_standard_streams_to_dev_null() -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: dup2 onto the standard descriptors of this process.
        if unsafe { libc::dup2(dev_null.as_raw_fd(), fd) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::time::{Duration, Instant};

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "edamame_posture_detach_{}_{}",
            name,
            std::process::id()
        ))
    }

    fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting for {}", what);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn detached_child_leads_its_own_session_in_tmp_with_umask_027() {
        let out = scratch("props");
        let _ = std::fs::remove_file(&out);
        let mut child = std::process::Command::new("/bin/sh");
        child.arg("-c").arg(format!(
            "{{ umask; pwd -P; if read -r line; then echo stdin=data; else echo stdin=eof; fi; }} > '{}' 2>&1; sleep 2",
            out.display()
        ));
        detach(&mut child);
        let mut child = child.spawn().expect("spawn the detached child");
        let pid = child.id() as libc::pid_t;

        // A new session and process group led by the child; the test's own
        // session is left.
        let (sid, pgid, own_sid) =
            unsafe { (libc::getsid(pid), libc::getpgid(pid), libc::getsid(0)) };
        assert_eq!(sid, pid, "session leader");
        assert_eq!(pgid, pid, "process group leader");
        assert_ne!(sid, own_sid);

        wait_for("the child's report", || {
            std::fs::read_to_string(&out)
                .map(|t| t.lines().count() >= 3)
                .unwrap_or(false)
        });
        let report = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines[0].trim_start_matches('0'), "27", "umask: {}", report);
        let tmp = std::fs::canonicalize(DAEMON_WORKING_DIRECTORY).unwrap();
        assert_eq!(std::path::Path::new(lines[1]), tmp.as_path());
        assert_eq!(lines[2], "stdin=eof");
        assert!(child.wait().unwrap().success());
        let _ = std::fs::remove_file(&out);
    }

    /// Child half of the supervisor test: this test binary re-executed as a
    /// supervisor of `sleep`, the parent half watching it from outside.
    const SUPERVISE_PID_FILE_ENV: &str = "EDAMAME_POSTURE_TEST_SUPERVISE_PID_FILE";

    #[test]
    fn supervisor_holds_the_pid_file_lock_while_its_daemon_runs() {
        if let Ok(pid_file) = std::env::var(SUPERVISE_PID_FILE_ENV) {
            let mut daemon = std::process::Command::new("/bin/sh");
            daemon.arg("-c").arg("sleep 10");
            std::process::exit(supervise(std::path::Path::new(&pid_file), &mut daemon));
        }

        let pid_file = scratch("pid");
        let _ = std::fs::remove_file(&pid_file);
        let supervisor = |stderr: std::process::Stdio| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "daemon::tests::supervisor_holds_the_pid_file_lock_while_its_daemon_runs",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(SUPERVISE_PID_FILE_ENV, &pid_file)
                .stdout(std::process::Stdio::null())
                .stderr(stderr);
            detach(&mut command);
            command
        };
        let mut first = supervisor(std::process::Stdio::null())
            .spawn()
            .expect("spawn the supervisor");
        let first_pid = first.id();
        wait_for("the pid file", || {
            std::fs::read_to_string(&pid_file)
                .map(|t| t == format!("{}\n", first_pid))
                .unwrap_or(false)
        });

        // Locked while the daemon runs: a second supervisor fails at once,
        // and says why on the stderr it was given.
        let file = std::fs::File::open(&pid_file).unwrap();
        assert_ne!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let second = supervisor(std::process::Stdio::piped()).output().unwrap();
        assert_eq!(second.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&second.stderr).contains("unable to lock pid file"),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        // 0666 under the detached umask (027), as the daemonize crate made it.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&pid_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "pid file mode {:o}", mode);

        // The supervisor exits 0 once its daemon has, releasing the lock.
        assert_eq!(first.wait().unwrap().code(), Some(0));
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let _ = std::fs::remove_file(&pid_file);
    }
}
