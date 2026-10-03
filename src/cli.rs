use crate::parse_digits_only;
use crate::parse_email;
use crate::parse_fqdn;
use crate::parse_signature;
use crate::parse_username;
use crate::CORE_VERSION;
use clap::{arg, Arg, ArgAction, Command};
use clap_complete::Shell;

pub fn build_cli() -> Command {
    // Turn it into a &'static str by leaking it
    let core_version_runtime: String = CORE_VERSION.to_string();
    let core_version_static: &'static str = Box::leak(core_version_runtime.into_boxed_str());

    Command::new("edamame_posture")
        .version(core_version_static)
        .author("EDAMAME Technologies")
        .about("CLI interface to edamame_core")
    .subcommand(
        Command::new("completion")
            .about("Generate shell completion scripts")
            .arg(arg!(<SHELL> "The shell to generate completions for")
                .value_parser(clap::value_parser!(Shell)))
    )
    .arg(
        arg!(
            -v --verbose ... "Verbosity level (-v: info, -vv: debug, -vvv: trace)"
        )
        .required(false)
        .action(ArgAction::Count)
        .global(true),
    )
    ////////////////
    // Base commands
    ////////////////
    .subcommand(Command::new("get-score").alias("score").about("Get score information"))
    .subcommand(Command::new("lanscan").about("Performs a LAN scan"))
    .subcommand(
        Command::new("capture")
            .about("Capture packets")
            .arg(
                arg!([SECONDS] "Number of seconds to capture")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            )
            .arg(
                arg!([WHITELIST_NAME] "Whitelist name")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([ZEEK_FORMAT] "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([LOCAL_TRAFFIC] "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            ),
    )
    .subcommand(Command::new("get-core-info").about("Get core information"))
    .subcommand(Command::new("get-device-info").about("Get device information"))
    .subcommand(Command::new("get-system-info").about("Get system information"))
    .subcommand(
        Command::new("request-pin")
            .about("Request PIN")
            .arg(
                arg!(<USER> "User name")
                    .required(true)
                    .value_parser(parse_username),
            )
            .arg(
                arg!(<DOMAIN> "Domain name")
                    .required(true)
                    .value_parser(parse_fqdn),
            ),
    )
    .subcommand(Command::new("get-core-version").about("Get core version"))
    .subcommand(
        Command::new("remediate-all-threats").alias("remediate").about("Remediate all threats but excluding remote login enabled and local firewall disabled as well as other threats specified in the comma separated list").arg(
            arg!(<REMEDIATIONS> "Remediations to skip (comma separated list), by default 'remote login enabled' and 'local firewall disabled' are skipped in order to avoid lockdown issues")
                .required(false)
                .default_value("remote login enabled,local firewall disabled"),
        ),
    )
    .subcommand(Command::new("remediate-all-threats-force").about("Remediate all threats, including threats that could lock you out of the system, use with caution!"))
    .subcommand(Command::new("remediate-threat").about("Remediate a threat").arg(
        arg!(<THREAT_ID> "Threat ID")
            .required(true)
            .value_parser(clap::value_parser!(String)),
    ))
    .subcommand(
        Command::new("dismiss-device")
            .about("Dismiss all ports on a device")
            .arg(
                arg!(<IP_ADDRESS> "Device IP address")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("dismiss-device-port")
            .about("Dismiss a specific device port")
            .arg(
                arg!(<IP_ADDRESS> "Device IP address")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!(<PORT> "Port number")
                    .required(true)
                    .value_parser(clap::value_parser!(u16)),
            ),
    )
    .subcommand(
        Command::new("dismiss-session")
            .about("Dismiss a session by UID")
            .arg(
                arg!(<SESSION_UID> "Session UID")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("dismiss-session-process")
            .about("Dismiss future sessions for a process by UID")
            .arg(
                arg!(<SESSION_UID> "Session or process UID")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(Command::new("rollback-threat").about("Rollback a threat").arg(
        arg!(<THREAT_ID> "Threat ID")
            .required(true)
            .value_parser(clap::value_parser!(String)),
    ))
    .subcommand(Command::new("list-threats").about("List all threat names"))
    .subcommand(Command::new("get-threat-info").about("Get threat information").arg(
        arg!(<THREAT_ID> "Threat ID")
            .required(true)
            .value_parser(clap::value_parser!(String)),
    ))
    .subcommand(Command::new("request-signature").about("Report the security posture anonymously and get a signature for later retrieval"))
    .subcommand(Command::new("request-report").about("Send a report from a signature to an email address").arg(
        arg!(<EMAIL> "Email address")
                .required(true)
                .value_parser(parse_email)).arg(
            arg!(<SIGNATURE> "SignaturCe")
                .required(true)
                .value_parser(parse_signature),
        ),
    )
    .subcommand(
        Command::new("check-policy-for-domain")
            .about("Check the current score against a policy for a specific domain in the hub")
            .arg(
                arg!(<DOMAIN> "Domain name")
                    .required(true)
                    .value_parser(parse_fqdn),
            )
            .arg(
                arg!(<POLICY_NAME> "Policy name")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
    )
    .subcommand(Command::new("check-policy-for-domain-with-signature").about("A score associated with a signature, against of policy for a specific domain in the hub").arg(
        arg!(<SIGNATURE> "Signature")
            .required(true)
            .value_parser(parse_signature),
        )
        .arg(
            arg!(<DOMAIN> "Domain name")
                .required(true)
                .value_parser(parse_fqdn),
        )
        .arg(
                arg!(<POLICY_NAME> "Policy name")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
        )
    )
    .subcommand(
        Command::new("check-policy")
            .about("Check locally if the current system meets the specified policy requirements")
            .arg(
                arg!(<MINIMUM_SCORE> "Minimum required score (value between 0.0 and 5.0)")
                    .required(true)
                    .value_parser(|s: &str| -> Result<f32, String> {
                        // Try to parse as float first
                        if let Ok(val) = s.parse::<f32>() {
                            return Ok(val);
                        }
                        // If that fails, try to parse as integer, then convert to float
                        match s.parse::<i32>() {
                            Ok(val) => Ok(val as f32),
                            Err(_) => Err(format!("Invalid minimum score: '{}'. Expected a number between 0.0 and 5.0", s))
                        }
                    }),
            )
            .arg(
                arg!(<THREAT_IDS> "Comma separated list of threat IDs that must be fixed")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([TAG_PREFIXES] "Comma separated list of tag prefixes")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
    )
    .subcommand(Command::new("get-tag-prefixes").about("Get threat model tag prefixes"))
    //////////////////////
    // Background commands
    //////////////////////
    .subcommand(Command::new("background-logs").alias("logs").about("Display logs from the background process"))
    .subcommand(
        Command::new("background-wait-for-connection")
            .alias("wait-for-connection")
            .about("Wait for connection of the background process")
            .arg(
                arg!([TIMEOUT] "Timeout in seconds")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-get-sessions")
            .alias("get-sessions")
            .about("Get connections from the background process")
            .arg(
                arg!(--"zeek-format" "Output sessions in Zeek format")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(--"include-local-traffic" "Include local traffic in the output")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(--"fail-on-whitelist" "Exit with code 1 if whitelist violations are detected")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(--"fail-on-blacklist" "Exit with code 1 if blacklisted sessions are detected")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(--"fail-on-anomalous" "Exit with code 1 if anomalous sessions are detected")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    )
    .subcommand(
        Command::new("background-get-exceptions")
            .alias("get-exceptions")
            .about("Get non-conforming connections from the background process")
            .arg(
                arg!([ZEEK_FORMAT] "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([LOCAL_TRAFFIC] "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            ),
    )
    .subcommand(Command::new("background-threats-info").alias("get-threats-info").about("Get threats information of the background process"))
    .subcommand(
        Command::new("foreground-start")
            .about("Start reporting in the foreground (used by the systemd service)")
            .args(start_common_args()),
    )
    .subcommand(
        Command::new("background-start")
            .alias("start")
            .about("Start reporting background process")
            .args(start_common_args()),
    )
    .subcommand(Command::new("background-stop").alias("stop").about("Stop reporting background process"))
    ////////////////
    // Native service (LaunchDaemon / Windows service / systemd unit)
    ////////////////
    .subcommands(crate::service::service_subcommands())
    ////////////////
    // MCP Server commands
    ////////////////
    .subcommand(
        Command::new("background-mcp-start").alias("mcp-start").about("Start MCP server for external AI clients (e.g., Claude Desktop)")
            .arg(
                arg!([PORT] "Port to listen on")
                    .required(false)
                    .default_value("3000")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                arg!([PSK] "Pre-shared key for authentication (min 32 chars)")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                Arg::new("all-interfaces")
                    .long("all-interfaces")
                    .help("Listen on all interfaces")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
    )
    .subcommand(Command::new("background-mcp-stop").alias("mcp-stop").about("Stop MCP server"))
    .subcommand(Command::new("background-mcp-status").alias("mcp-status").about("Get MCP server status"))
    .subcommand(Command::new("background-mcp-generate-psk").alias("mcp-generate-psk").about("Generate a secure PSK for MCP server"))
    .subcommand(Command::new("background-agentic-summary").alias("agentic-summary").about("Get comprehensive agentic status summary (provider, mode, todos, actions, Slack)"))
    .subcommand(
        Command::new("background-agentic-start")
            .alias("agentic-start")
            .about("Start only the security assistant (auto-remediation) loop in the background process; attack-pattern-start and divergence-start drive the detection engines")
            .arg(
                arg!([MODE] "Loop mode: auto (execute) or analyze (review)")
                    .required(false)
                    .default_value("analyze")
                    .value_parser(["auto", "analyze"]),
            )
            .arg(
                arg!([INTERVAL_SECS] "Tick interval in seconds (minimum 300)")
                    .required(false)
                    .default_value("3600")
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-agentic-stop")
            .alias("agentic-stop")
            .about("Stop only the security assistant loop; the detection engines keep running"),
    )
    .subcommand(
        Command::new("background-agentic-status")
            .alias("agentic-status")
            .about("Get the security assistant loop status"),
    )
    .subcommand(
        Command::new("background-divergence-upsert-model")
            .alias("divergence-upsert-model")
            .about("Upsert a behavioral model JSON payload for divergence detection")
            .arg(
                arg!(<MODEL_JSON> "Behavioral model JSON")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-upsert-model-from-file")
            .alias("divergence-upsert-model-from-file")
            .about("Upsert a behavioral model JSON payload from file")
            .arg(
                arg!(<MODEL_FILE> "Path to behavioral model JSON file")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-get-model")
            .alias("divergence-get-model")
            .about("Get current behavioral model used by divergence engine"),
    )
    .subcommand(
        Command::new("background-divergence-clear-model")
            .alias("divergence-clear-model")
            .about("Clear current behavioral model"),
    )
    .subcommand(
        Command::new("background-divergence-start")
            .alias("divergence-start")
            .about("Start divergence engine in background process")
            .arg(
                arg!([INTERVAL_SECS] "Tick interval in seconds")
                    .required(false)
                    .default_value("120")
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-adjudication-mode")
            .alias("divergence-adjudication-mode")
            .about("Set whether the divergence engine consults the LLM: llm (deterministic fallback when the LLM is unavailable), deterministic (never consult the LLM), or auto (the core default: follow the LLM connection; the daemon pins llm when --agentic-mode asked for the LLM). advisory is accepted and behaves as llm for this engine.")
            .arg(
                arg!(<MODE> "Adjudication mode")
                    .value_parser(["auto", "llm", "advisory", "deterministic"]),
            ),
    )
    .subcommand(
        Command::new("background-divergence-stop")
            .alias("divergence-stop")
            .about("Stop divergence engine in background process"),
    )
    .subcommand(
        Command::new("background-divergence-status")
            .alias("divergence-status")
            .about("Get divergence engine status"),
    )
    .subcommand(
        Command::new("background-divergence-get-verdict")
            .alias("divergence-get-verdict")
            .about("Get latest divergence verdict"),
    )
    .subcommand(
        Command::new("background-divergence-get-history")
            .alias("divergence-get-history")
            .about("Get divergence verdict history")
            .arg(
                arg!([LIMIT] "Maximum number of history entries")
                    .required(false)
                    .default_value("20")
                    .value_parser(clap::value_parser!(usize)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-dismiss")
            .alias("divergence-dismiss")
            .about("Dismiss divergence evidence by finding key")
            .arg(
                arg!(<FINDING_KEY> "Finding key to dismiss")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-undismiss")
            .alias("divergence-undismiss")
            .about("Restore previously dismissed divergence evidence")
            .arg(
                arg!(<FINDING_KEY> "Finding key to restore")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-divergence-reset-suppressions")
            .alias("divergence-reset-suppressions")
            .about("Reset all divergence suppressions"),
    )
    ////////////////
    // Attack Pattern Detector commands (model-independent)
    //
    // Since 2.0.0 the canonical names use "attack-pattern"; the legacy names use "vulnerability" and are kept as aliases for one release; both short forms also work. Naming:
    // "attack-pattern". Both work via clap aliases. See the workspace rules
    // (Vulnerability -> Attack Pattern Detection Terminology Transition).
    ////////////////
    .subcommand(
        Command::new("background-attack-pattern-start")
            .alias("vulnerability-start")
            .alias("background-vulnerability-start")
            .alias("attack-pattern-start")
            .about("Start attack pattern detector in background process")
            .arg(
                arg!([INTERVAL_SECS] "Tick interval in seconds")
                    .required(false)
                    .default_value("60")
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-adjudication-mode")
            .alias("vulnerability-adjudication-mode")
            .alias("background-vulnerability-adjudication-mode")
            .alias("attack-pattern-adjudication-mode")
            .about("Set how the attack pattern detector publishes without the LLM adjudicator: llm (a tick the LLM did not answer is withheld; the daemon pins this when --agentic-mode asked for the LLM), advisory (publish the deterministic result when the LLM fails), deterministic (never consult the LLM), auto (the core default: advisory with LLM credentials, deterministic without)")
            .arg(
                arg!(<MODE> "Adjudication mode")
                    .value_parser(["auto", "llm", "advisory", "deterministic"]),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-stop")
            .alias("vulnerability-stop")
            .alias("background-vulnerability-stop")
            .alias("attack-pattern-stop")
            .about("Stop attack pattern detector in background process"),
    )
    .subcommand(
        Command::new("background-attack-pattern-status")
            .alias("vulnerability-status")
            .alias("background-vulnerability-status")
            .alias("attack-pattern-status")
            .about("Get attack pattern detector status")
            .arg(
                arg!(--"fail-on-findings" "Exit 1 on active HIGH/CRITICAL findings; exit 2 when the detector is not running, its loop is stalled, or its latest tick stays withheld (LLM did not answer) past one interval")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("since")
                    .long("since")
                    .value_name("RFC3339")
                    .requires("fail-on-findings")
                    .help("With --fail-on-findings: exit 1 only on findings first seen at or after this time (e.g. 2026-09-29T08:00:00Z, the CI job's start); older active findings are printed as warnings with their first-seen time and stay in the history")
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-findings")
            .alias("vulnerability-findings")
            .alias("background-vulnerability-findings")
            .alias("attack-pattern-findings")
            .about("Dump active runtime attack pattern findings as JSON")
            .arg(
                arg!(--"active-only" "Filter out dismissed findings before printing")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-dismiss")
            .alias("vulnerability-dismiss")
            .alias("background-vulnerability-dismiss")
            .alias("attack-pattern-dismiss")
            .about("Dismiss attack pattern finding by finding key")
            .arg(
                arg!(<FINDING_KEY> "Finding key to dismiss")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-undismiss")
            .alias("vulnerability-undismiss")
            .alias("background-vulnerability-undismiss")
            .alias("attack-pattern-undismiss")
            .about("Restore previously dismissed attack pattern finding")
            .arg(
                arg!(<FINDING_KEY> "Finding key to restore")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-attack-pattern-reset-suppressions")
            .alias("vulnerability-reset-suppressions")
            .alias("background-vulnerability-reset-suppressions")
            .alias("attack-pattern-reset-suppressions")
            .about("Reset all attack pattern suppressions"),
    )
    .subcommand(
        Command::new("background-attack-pattern-debug-trace")
            .alias("vulnerability-debug-trace")
            .alias("background-vulnerability-debug-trace")
            .alias("attack-pattern-debug-trace")
            .about(
                "Dump VulnerabilityDebugTrace JSON for a past attack pattern report \
                 (FP corpus capture / detector replay input)",
            )
            .arg(
                arg!(--"latest" "Resolve report_id from the latest in-memory report (default when no REPORT_ID given)")
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .conflicts_with("REPORT_ID"),
            )
            .arg(
                arg!([REPORT_ID] "Explicit report_id to fetch (overrides --latest)")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-clear-attack-pattern-history")
            .alias("clear-vulnerability-history")
            .alias("background-clear-vulnerability-history")
            .alias("clear-attack-pattern-history")
            .about("Clear the daemon's in-memory and persisted attack pattern action_history (test-induced FP cleanup)"),
    )
    .subcommand(
        Command::new("background-agentic-dismiss-with-scope")
            .alias("agentic-dismiss-with-scope")
            .alias("vulnerability-dismiss-with-scope")
            .about("Create a recurrence-aware dismissal rule from an agentic_dismiss_with_scope JSON request")
            .arg(
                arg!(<REQUEST_JSON> "JSON request accepted by agentic_dismiss_with_scope")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-agentic-list-dismissal-rules")
            .alias("agentic-list-dismissal-rules")
            .alias("dismissal-rules")
            .about("List recurrence-aware dismissal rules")
            .arg(
                arg!(--domain <DOMAIN> "Optional domain filter: vulnerability, divergence or session")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-agentic-remove-dismissal-rule")
            .alias("agentic-remove-dismissal-rule")
            .alias("remove-dismissal-rule")
            .about("Remove a recurrence-aware dismissal rule by id")
            .arg(
                arg!(<RULE_ID> "Dismissal rule id to remove")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    ////////////////
    // Agent Visibility commands (MCP discovery, agent component inventory, capability graph,
    // recursive-agent detection). All reads lazily refresh a
    // structural snapshot daemon-side, so a single-shot CLI call returns data
    // without a separate refresh step.
    ////////////////
    .subcommand(
        Command::new("background-agent-visibility-refresh")
            .alias("agent-visibility-refresh")
            .about("Force a fresh agent-visibility structural snapshot (MCP inventory, component inventories, capability graph)"),
    )
    .subcommand(
        Command::new("background-visibility-summary")
            .alias("visibility-summary")
            .about("Print compact agent-visibility rollup counts (endpoints, findings, component inventories, graph, recursion)"),
    )
    .subcommand(
        Command::new("background-mcp-inventory")
            .alias("mcp-inventory")
            .about("Dump the discovered MCP server inventory (endpoints + findings) as JSON"),
    )
    .subcommand(
        Command::new("background-mcp-findings")
            .alias("mcp-findings")
            .about("Dump MCP discovery risk findings as JSON"),
    )
    .subcommand(
        Command::new("background-agent-component-inventories")
            .alias("agent-component-inventories")
            .about("Dump the per-agent component inventory snapshots as JSON"),
    )
    .subcommand(
        Command::new("background-capability-graph")
            .alias("capability-graph")
            .about("Dump the agent capability graph (who-can-reach-what edges) as JSON"),
    )
    .subcommand(
        Command::new("background-recursion-risk")
            .alias("recursion-risk")
            .about("Dump recursive-agent / delegation-tree risk findings as JSON"),
    )
    ////////////////
    // Agent command-centre rollups (fleet overview, failure clusters,
    // budgets). Read-only joins over economics/TSDB/findings the daemon
    // already computes; budget set is operator-only.
    ////////////////
    .subcommand(
        Command::new("background-agent-fleet-overview")
            .alias("agent-fleet-overview")
            .about("Dump the agent fleet overview rollup (spend, sessions, errors, waste, top agents) as JSON")
            .arg(
                arg!([WINDOW_MINUTES] "Rollup window in minutes")
                    .required(false)
                    .default_value("1440")
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-agent-failure-clusters")
            .alias("agent-failure-clusters")
            .about("Dump deterministic tool-failure clusters (tool x error class) as JSON")
            .arg(
                arg!([WINDOW_MINUTES] "Clustering window in minutes")
                    .required(false)
                    .default_value("1440")
                    .value_parser(clap::value_parser!(u64)),
            )
            .arg(
                arg!(--agent <AGENT_TYPE> "Optional agent type filter (e.g. cursor, claude_code)")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-agent-budgets")
            .alias("agent-budgets")
            .about("Dump operator-set per-agent daily budgets joined with today's actuals as JSON"),
    )
    .subcommand(
        Command::new("background-set-agent-budget")
            .alias("set-agent-budget")
            .about("Set or clear the daily budget for one agent type (cap <= 0 clears that axis; both cleared removes the entry)")
            .arg(
                arg!(<AGENT_TYPE> "Agent type (e.g. cursor, claude_code, codex)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([DAILY_COST_USD_CAP] "Daily estimated-cost cap in USD (0 clears)")
                    .required(false)
                    .default_value("0")
                    .value_parser(clap::value_parser!(f64)),
            )
            .arg(
                arg!([DAILY_TOKEN_CAP] "Daily total-token cap (0 clears)")
                    .required(false)
                    .default_value("0")
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    ////////////////
    // Agent inventory + trust-zone queries (INC-10, Stage C). Reads are
    // operator/MCP-safe; mutators are operator-only (no MCP equivalent --
    // invariant I1).
    ////////////////
    .subcommand(
        Command::new("background-agent-inventory")
            .alias("agent-inventory")
            .about("Dump the agent inventory (installed / on-host / discovered / observer_enabled per agent) as JSON"),
    )
    .subcommand(
        Command::new("background-graph-reachability")
            .alias("graph-reachability")
            .about("Dump per-agent trust-zone reachability (who can cross out to an untrusted surface) as JSON"),
    )
    .subcommand(
        Command::new("background-effective-capabilities")
            .alias("effective-capabilities")
            .about("Dump per-agent effective (transitively reachable) capabilities as JSON"),
    )
    .subcommand(
        Command::new("background-metrics-history")
            .alias("metrics-history")
            .about("Dump the durable metrics-history time-series (agentic token/cost, LLM, network, process, file families) as JSON")
            .arg(
                arg!([FAMILY] "Metric family to filter (e.g. tokens_total_by_agent, est_cost_usd_by_agent, net_bytes_out_by_domain, files_by_label); omit or 'all' for every family")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                Arg::new("granularity")
                    .long("granularity")
                    .short('g')
                    .value_name("GRANULARITY")
                    .help("Bucket granularity: hourly (default) or daily")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                Arg::new("range-minutes")
                    .long("range-minutes")
                    .short('r')
                    .value_name("MINUTES")
                    .help("Look-back window in minutes from now (default 1440 = 24h)")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-augmentation-report")
            .alias("augmentation-report")
            .alias("self-augmentation-report")
            .about("Dump the LLM-free self-augmentation report (composite score + Coverage/Utilization/Diversity/Leverage/Efficiency/Trend sub-scores, coverage level, per-skill structural quality, per-workspace context tax, and estimate-flagged task economics) as JSON")
            .arg(
                Arg::new("window-minutes")
                    .long("window-minutes")
                    .short('w')
                    .value_name("MINUTES")
                    .help("Usage-classification window in minutes (default 1440 = 24h)")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-mcp-endpoints")
            .alias("mcp-endpoints")
            .about("Dump the discovered MCP endpoint inventory (servers + transports) as JSON"),
    )
    .subcommand(
        Command::new("background-visibility-capture-tier")
            .alias("visibility-capture-tier")
            .about("Print the active agent-visibility capture tier (structural / behavioral / forensic)"),
    )
    .subcommand(
        Command::new("background-set-visibility-capture-tier")
            .alias("set-visibility-capture-tier")
            .about("Operator: set the agent-visibility capture tier")
            .arg(
                arg!(<TIER> "Capture tier: structural | behavioral | forensic")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    ////////////////
    // INC-5 Flight Recorder: hash-chained run provenance + causal projection.
    // All reads; refresh recomputes the provenance log.
    ////////////////
    .subcommand(
        Command::new("background-refresh-run-provenance")
            .alias("refresh-run-provenance")
            .about("Recompute the hash-chained run-provenance log from current telemetry"),
    )
    .subcommand(
        Command::new("background-list-runs")
            .alias("list-runs")
            .about("List recent agent runs from the flight recorder as JSON"),
    )
    .subcommand(
        Command::new("background-run-provenance")
            .alias("run-provenance")
            .about("Dump the hash-chained provenance event log for one run as JSON")
            .arg(
                arg!(<RUN_ID> "Run identifier (see background-list-runs)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-explain-run-event")
            .alias("explain-run-event")
            .about("Explain the causal projection for one provenance event as JSON")
            .arg(
                arg!(<RUN_ID> "Run identifier")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!(<EVENT_ID> "Event identifier within the run")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    ////////////////
    // INC-6 Drift Timeline: goal/delegation drift axes over verdict + window
    // history. All reads; refresh recomputes the drift snapshot.
    ////////////////
    .subcommand(
        Command::new("background-refresh-agent-drift")
            .alias("refresh-agent-drift")
            .about("Recompute the per-agent goal/delegation drift snapshot"),
    )
    .subcommand(
        Command::new("background-agent-drift")
            .alias("agent-drift")
            .about("Dump the per-agent goal/delegation drift rollup as JSON"),
    )
    .subcommand(
        Command::new("background-agent-drift-timeline")
            .alias("agent-drift-timeline")
            .about("Dump one agent's drift timeline (verdict + window history) as JSON")
            .arg(
                arg!(<AGENT_KEY> "Agent key (agent_type:agent_instance_id)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-explain-agent-drift")
            .alias("explain-agent-drift")
            .about("Explain one agent drift timeline event as JSON")
            .arg(
                arg!(<AGENT_KEY> "Agent key (agent_type:agent_instance_id)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!(<EVENT_ID> "Drift event identifier within the timeline")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    ////////////////
    // INC-7 Data-Flow Map: taint-class -> sink trust-zone edges + cross-boundary
    // findings. All reads; refresh recomputes the maps.
    ////////////////
    .subcommand(
        Command::new("background-refresh-dataflow-maps")
            .alias("refresh-dataflow-maps")
            .about("Recompute the per-agent sensitive data-flow maps"),
    )
    .subcommand(
        Command::new("background-dataflow-maps")
            .alias("dataflow-maps")
            .about("Dump all per-agent sensitive data-flow maps as JSON"),
    )
    .subcommand(
        Command::new("background-dataflow-map")
            .alias("dataflow-map")
            .about("Dump one agent's sensitive data-flow map as JSON")
            .arg(
                arg!(<AGENT_TYPE> "Agent type (e.g. cursor, claude_code, claude_desktop, openclaw)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    ////////////////
    // INC-8 Memory & RAG inventory: memory-store inventory + chunk-risk
    // heuristics. All reads; refresh recomputes the inventory.
    ////////////////
    .subcommand(
        Command::new("background-refresh-memory-inventory")
            .alias("refresh-memory-inventory")
            .about("Recompute the memory / RAG store inventory"),
    )
    .subcommand(
        Command::new("background-memory-inventory")
            .alias("memory-inventory")
            .about("Dump the memory / RAG store inventory with chunk-risk heuristics as JSON"),
    )
    ////////////////
    // INC-9 A2A mapping: agent-to-agent endpoint + comm-edge graph. All reads;
    // refresh recomputes the graph.
    ////////////////
    .subcommand(
        Command::new("background-refresh-a2a-graph")
            .alias("refresh-a2a-graph")
            .about("Recompute the agent-to-agent (A2A) communication graph"),
    )
    .subcommand(
        Command::new("background-a2a-graph")
            .alias("a2a-graph")
            .about("Dump the agent-to-agent (A2A) endpoint + comm-edge graph as JSON"),
    )
    ////////////////
    // Transcript Observer controls (per-agent host-side observation). Moved
    // from app-only control into the CLI so headless/posture deployments can
    // operate the observer that feeds divergence detection.
    ////////////////
    .subcommand(
        Command::new("background-observer-status")
            .alias("observer-status")
            .about("Print per-agent transcript observer status (discovered / enabled / last tick) as JSON"),
    )
    .subcommand(
        Command::new("background-observer-enable")
            .alias("observer-enable")
            .about("Enable the transcript observer for one agent type")
            .arg(
                arg!(<AGENT_TYPE> "Agent type to enable (e.g. cursor, claude_code, claude_desktop, openclaw)")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-observer-disable")
            .alias("observer-disable")
            .about("Disable (pause) the transcript observer for one agent type")
            .arg(
                arg!(<AGENT_TYPE> "Agent type to disable")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-observer-tick")
            .alias("observer-tick")
            .about("Run a one-shot transcript observer tick for one agent type")
            .arg(
                arg!(<AGENT_TYPE> "Agent type to tick")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(Command::new("background-status").alias("status").about("Get status of reporting background process"))
    .subcommand(Command::new("background-last-report-signature").alias("get-last-report-signature").about("Get last report signature of background process"))
    .subcommand(Command::new("background-get-history").alias("get-history").about("Get history of score modifications"))
    .subcommand(
        Command::new("background-start-disconnected")
            .about("Start the background process in disconnected mode (without domain authentication)")
            .args(disconnected_start_args()),
    )
    .subcommand(
        Command::new("background-set-custom-whitelists")
            .alias("set-custom-whitelists")
            .about("Set custom whitelists from JSON")
            .arg(
                arg!(<WHITELIST_JSON> "JSON string containing whitelist definitions")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-set-custom-whitelists-from-file")
            .alias("set-custom-whitelists-from-file")
            .about("Set custom whitelists from a file containing JSON")
            .arg(
                arg!(<WHITELIST_FILE> "The path to the whitelist file")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-create-custom-whitelists")
            .alias("create-custom-whitelists")
            .about("Create custom whitelists from current sessions")
            .arg(
                arg!(--"include-process" "Include process names in whitelist entries for stricter matching")
                    .required(false)
                    .action(clap::ArgAction::SetTrue),
            )
    )
    .subcommand(
        Command::new("background-create-and-set-custom-whitelists")
            .alias("create-and-set-custom-whitelists")
            .about("Create custom whitelists from current sessions and set them")
    )
    .subcommand(
        Command::new("background-set-whitelist")
            .alias("set-whitelist")
            .about("Enforce a named whitelist (github_ubuntu, github_macos, github_windows, github, builder, edamame); an empty name turns whitelist checks off. An unknown name exits 3: it is enforced as an empty list, so every egress session is non-conforming")
            .arg(
                arg!(<WHITELIST_NAME> "Name of the whitelist")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-evaluate-custom-whitelists-from-file")
            .alias("evaluate-custom-whitelists-from-file")
            .about("Check the observed egress sessions against the custom whitelist in a file (not the one the daemon has loaded). Exit 0: all conform; 1: some do not; 2: nothing could be checked (capture not running, daemon error); 3: the file does not load")
            .arg(
                arg!(<WHITELIST_FILE> "The path to the whitelist file")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                Arg::new("since")
                    .long("since")
                    .value_name("RFC3339")
                    .help("Only sessions active at or after this time (e.g. 2026-09-29T08:00:00Z, the CI job's start)")
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!(--"json" "Print the daemon's JSON result instead of a session list")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    )
    .subcommand(
        Command::new("background-augment-custom-whitelists-from-file")
            .alias("augment-custom-whitelists-from-file")
            .about("Print, as JSON, the custom whitelist in a file plus an entry for every observed egress session that does not conform to it (\"whitelist\", \"added\", \"evaluated\", \"non_conforming\"). The file is the base, not the daemon's live whitelist. Exit 2 when nothing could be observed, 3 when the file does not load")
            .arg(
                arg!(<WHITELIST_FILE> "The path to the whitelist file")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                Arg::new("since")
                    .long("since")
                    .value_name("RFC3339")
                    .help("Only sessions active at or after this time (e.g. the CI job's start)")
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-set-custom-blacklists")
            .alias("set-custom-blacklists")
            .about("Set custom blacklists from JSON")
            .arg(
                arg!(<BLACKLIST_JSON> "JSON string containing blacklist definitions")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            )
    )
    .subcommand(
        Command::new("background-set-custom-blacklists-from-file")
            .alias("set-custom-blacklists-from-file")
            .about("Set custom blacklists from a file containing JSON")
            .arg(
                arg!(<BLACKLIST_FILE> "The path to the blacklist file")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(Command::new("background-score").alias("get-background-score").about("Get security score from the background process"))
    .subcommand(
        Command::new("background-get-anomalous-sessions")
            .alias("get-anomalous-sessions")
            .about("Get anomalous connections detected by the background process")
            .arg(
                arg!([ZEEK_FORMAT] "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            ),
    )
    .subcommand(
        Command::new("background-get-blacklisted-sessions")
            .alias("get-blacklisted-sessions")
            .about("Get blacklisted connections detected by the background process")
            .arg(
                arg!([ZEEK_FORMAT] "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            ),
    )
    .subcommand(Command::new("background-get-blacklists").alias("get-blacklists").about("Get blacklists from the background process"))
    .subcommand(Command::new("background-get-whitelists").alias("get-whitelists").about("Get whitelists from the background process"))
    .subcommand(Command::new("background-get-whitelist-name").alias("get-whitelist-name").about("Get the current whitelist name from the background process"))
    ////////////////////
    // Custom whitelist utility commands
    ////////////////////
    .subcommand(Command::new("augment-custom-whitelists")
        .about("Augment the current custom whitelist locally using current whitelist exceptions"))
    .subcommand(Command::new("merge-custom-whitelists")
        .about("Merge two custom whitelist JSON strings into one consolidated whitelist")
        .arg(arg!(<WHITELIST_JSON_1> "First whitelist JSON string")
            .required(true)
            .value_parser(clap::value_parser!(String)))
        .arg(arg!(<WHITELIST_JSON_2> "Second whitelist JSON string")
            .required(true)
            .value_parser(clap::value_parser!(String))))
    .subcommand(Command::new("merge-custom-whitelists-from-files")
        .about("Merge two custom whitelist JSON files into one consolidated whitelist")
        .arg(arg!(<WHITELIST_FILE_1> "First whitelist JSON file path")
            .required(true)
            .value_parser(clap::value_parser!(String)))
        .arg(arg!(<WHITELIST_FILE_2> "Second whitelist JSON file path")
            .required(true)
            .value_parser(clap::value_parser!(String))))
    .subcommand(Command::new("compare-custom-whitelists")
        .about("Compare two custom whitelist JSON strings and return percentage difference")
        .arg(arg!(<WHITELIST_JSON_1> "First whitelist JSON string")
            .required(true)
            .value_parser(clap::value_parser!(String)))
        .arg(arg!(<WHITELIST_JSON_2> "Second whitelist JSON string")
            .required(true)
            .value_parser(clap::value_parser!(String))))
    .subcommand(Command::new("compare-custom-whitelists-from-files")
        .about("Compare two custom whitelist JSON files and return percentage difference")
        .arg(arg!(<WHITELIST_FILE_1> "First whitelist JSON file path")
            .required(true)
            .value_parser(clap::value_parser!(String)))
        .arg(arg!(<WHITELIST_FILE_2> "Second whitelist JSON file path")
            .required(true)
            .value_parser(clap::value_parser!(String))))
    ////////////////////
    // File Integrity Monitoring commands
    ////////////////////
    .subcommand(
        Command::new("background-start-file-monitor")
            .alias("start-file-monitor")
            .about("Start file integrity monitoring in the background process")
            .arg(
                arg!(--"paths" <PATHS> "Comma-separated paths to monitor (default: auto-detected)")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            ),
    )
    .subcommand(
        Command::new("background-stop-file-monitor")
            .alias("stop-file-monitor")
            .about("Stop file integrity monitoring"),
    )
    .subcommand(
        Command::new("background-file-monitor-status")
            .alias("file-monitor-status")
            .about("Get file integrity monitoring status"),
    )
    .subcommand(
        Command::new("background-get-file-events")
            .alias("get-file-events")
            .about("Get file events from the background process")
            .arg(
                arg!(--"fail-on-suspicious" "Exit with code 1 if suspicious file events are detected")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    )
    .subcommand(
        Command::new("background-clear-file-events")
            .alias("clear-file-events")
            .about("Clear file event history"),
    )
}

/// `--agentic-mode` values. `disabled` leaves the persisted agentic state as
/// the operator last set it (the default: a restart never overwrites it);
/// `off` turns agentic protection off (the Assistant, attack pattern
/// detection and divergence detection) through the daemon's RPC.
pub const AGENTIC_MODES: [&str; 4] = ["auto", "analyze", "off", "disabled"];

/// Where the PIN of a start command came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    None,
    CommandLine,
    Environment,
    File,
}

/// The Hub PIN of a start command, from `--pin-file`, `EDAMAME_PIN` or
/// `--pin` (in that order of preference; `--pin-file` and `--pin` conflict).
/// Warns on stderr when the PIN came from the command line (visible in the
/// process list) or from a file other accounts can read. `EDAMAME_PIN` is
/// removed from the environment once read, so the daemon's own children
/// (agent CLIs, the cancel-pipeline script) never inherit it.
pub fn resolve_pin(matches: &clap::ArgMatches) -> Result<(String, PinSource), String> {
    use clap::parser::ValueSource;
    let resolved = if let Some(path) = matches.get_one::<std::path::PathBuf>("pin_file") {
        (read_pin_file(path)?, PinSource::File)
    } else {
        let pin = matches
            .get_one::<String>("pin")
            .cloned()
            .unwrap_or_default();
        match matches.value_source("pin") {
            Some(ValueSource::CommandLine) if !pin.is_empty() => {
                eprintln!(
                    "Warning: --pin puts the PIN in the process list; use the EDAMAME_PIN environment variable or --pin-file instead."
                );
                (pin, PinSource::CommandLine)
            }
            Some(ValueSource::EnvVariable) if !pin.is_empty() => (pin, PinSource::Environment),
            _ => (String::new(), PinSource::None),
        }
    };
    std::env::remove_var("EDAMAME_PIN");
    Ok(resolved)
}

/// The PIN in `path`: its first line, trimmed, digits only. Warns when the
/// file is readable or writable by group or others (unix).
pub fn read_pin_file(path: &std::path::Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read PIN file {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "Warning: PIN file {} is accessible to other accounts (mode {:o}); chmod 600 it.",
                    path.display(),
                    mode
                );
            }
        }
    }
    let pin = text.lines().next().unwrap_or("").trim().to_string();
    if pin.is_empty() {
        return Err(format!("PIN file {} is empty", path.display()));
    }
    parse_digits_only(&pin)
}

/// The Hub-managed configuration opt-in the daemon reads from its
/// environment (`--accept-managed-config`).
pub const ACCEPT_MANAGED_CONFIG_ENV: &str = "EDAMAME_ACCEPT_MANAGED_CONFIG";

/// Environment variable carrying a Hub enrollment token (MDM deployment).
pub const ENROLLMENT_TOKEN_ENV: &str = "EDAMAME_ENROLLMENT_TOKEN";

/// The Hub enrollment token of a start command, from
/// `--enrollment-token-file`, `EDAMAME_ENROLLMENT_TOKEN` or
/// `--enrollment-token` (warned: visible in the process list). The variable
/// is removed from this process's environment once read; the caller hands
/// the token to the daemon explicitly. Empty when none was given.
pub fn resolve_enrollment_token(matches: &clap::ArgMatches) -> Result<String, String> {
    use clap::parser::ValueSource;
    let token = if let Some(path) = matches.get_one::<std::path::PathBuf>("enrollment_token_file") {
        read_secret_file(path, "enrollment token")?
    } else {
        let token = matches
            .get_one::<String>("enrollment_token")
            .cloned()
            .unwrap_or_default();
        if matches.value_source("enrollment_token") == Some(ValueSource::CommandLine)
            && !token.is_empty()
        {
            eprintln!(
                "Warning: --enrollment-token puts the token in the process list; use the EDAMAME_ENROLLMENT_TOKEN environment variable or --enrollment-token-file instead."
            );
        }
        token.trim().to_string()
    };
    std::env::remove_var(ENROLLMENT_TOKEN_ENV);
    Ok(token)
}

/// First line of a secret file, trimmed; warns when other accounts can
/// read or write it (unix).
fn read_secret_file(path: &std::path::Path, what: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {} file {}: {}", what, path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "Warning: {} file {} is accessible to other accounts (mode {:o}); chmod 600 it.",
                    what,
                    path.display(),
                    mode
                );
            }
        }
    }
    let value = text.lines().next().unwrap_or("").trim().to_string();
    if value.is_empty() {
        return Err(format!("{} file {} is empty", what, path.display()));
    }
    Ok(value)
}

fn start_common_args() -> Vec<Arg> {
    vec![
        Arg::new("user")
            .long("user")
            .short('u')
            .value_name("USER")
            .help("User name")
            .value_parser(parse_username)
            .default_value(""),
        Arg::new("domain")
            .long("domain")
            .short('d')
            .value_name("DOMAIN")
            .help("Domain name")
            .value_parser(parse_fqdn)
            .default_value(""),
        Arg::new("pin")
            .long("pin")
            .short('p')
            .value_name("PIN")
            .help("PIN. Prefer the EDAMAME_PIN environment variable or --pin-file: a PIN on the command line is visible in the process list")
            .env("EDAMAME_PIN")
            .hide_env_values(true)
            .value_parser(parse_digits_only)
            .default_value(""),
        Arg::new("pin_file")
            .long("pin-file")
            .value_name("PATH")
            .help("Read the PIN from this file (first line; keep it 0600, owner-only)")
            .conflicts_with("pin")
            .value_parser(clap::value_parser!(std::path::PathBuf)),
        Arg::new("enrollment_token")
            .long("enrollment-token")
            .value_name("TOKEN")
            .help("Hub enrollment token (MDM deployment): enrolls this device for --user/--domain without the user's PIN. Prefer the EDAMAME_ENROLLMENT_TOKEN environment variable or --enrollment-token-file: a token on the command line is visible in the process list")
            .env(ENROLLMENT_TOKEN_ENV)
            .hide_env_values(true)
            .value_parser(clap::value_parser!(String)),
        Arg::new("enrollment_token_file")
            .long("enrollment-token-file")
            .value_name("PATH")
            .help("Read the Hub enrollment token from this file (first line; keep it 0600, owner-only)")
            .conflicts_with("enrollment_token")
            .value_parser(clap::value_parser!(std::path::PathBuf)),
        Arg::new("llm_api_key")
            .long("llm-api-key")
            .short('k')
            .value_name("API_KEY")
            .help("EDAMAME Portal LLM API key for the security assistant (edamame provider)")
            .env("EDAMAME_LLM_API_KEY")
            .value_parser(clap::value_parser!(String)),
        Arg::new("accept_managed_config")
            .long("accept-managed-config")
            .value_name("always|sha256:FINGERPRINT")
            .help("Apply the domain's Hub-managed configuration for this target (CI/CD or posture): always (changes included), or only the configuration with this fingerprint. Without it a configuration is reported declined and the daemon stays connected")
            .env(ACCEPT_MANAGED_CONFIG_ENV)
            .num_args(0..=1)
            .default_missing_value("always")
            .value_parser(clap::value_parser!(String)),
        Arg::new("device_id")
            .long("device-id")
            .value_name("DEVICE_ID")
            .help("Device ID suffix to flag the endpoint as a CI/CD runner when provided")
            .value_parser(clap::value_parser!(String)),
        Arg::new("network_scan")
            .long("network-scan")
            .alias("lan-scan")
            .alias("lan-scanning")
            .short('n')
            .help("Enable LAN scanning and force LAN auto-scan on start")
            .action(ArgAction::SetTrue),
        Arg::new("packet_capture")
            .long("packet-capture")
            .alias("capture")
            .short('c')
            .help("Enable packet capture")
            .action(ArgAction::SetTrue),
        Arg::new("whitelist")
            .long("whitelist")
            .value_name("WHITELIST")
            .help("Whitelist name to enforce during capture")
            .value_parser(clap::value_parser!(String)),
        Arg::new("fail_on_whitelist")
            .long("fail-on-whitelist")
            .help("Treat whitelist violations as fatal (defaults to true when --whitelist is provided)")
            .action(ArgAction::SetTrue),
        Arg::new("fail_on_blacklist")
            .long("fail-on-blacklist")
            .help("Treat blacklist violations as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("fail_on_findings")
            .long("fail-on-findings")
            .help("Treat active attack pattern findings as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("include_local_traffic")
            .long("include-local-traffic")
            .alias("local-traffic")
            .help("Include local traffic in capture output")
            .action(ArgAction::SetTrue),
        Arg::new("agentic_mode")
            .long("agentic-mode")
            .value_name("MODE")
            .help("Security assistant mode: auto, analyze, off (turn the Assistant and both detection engines off) or disabled (leave them as last set)")
            .default_value("disabled")
            .value_parser(AGENTIC_MODES),
        Arg::new("agentic_provider")
            .long("agentic-provider")
            .value_name("PROVIDER")
            .help("LLM provider: edamame (Portal), claude, openai, ollama, none")
            .value_parser(["edamame", "claude", "openai", "ollama", "none"]),
        Arg::new("agentic_interval")
            .long("agentic-interval")
            .value_name("SECONDS")
            .help("Interval in seconds for automated todo processing (default: 3600)")
            .default_value("3600")
            .value_parser(clap::value_parser!(u64)),
        Arg::new("cancel_on_violation")
            .long("cancel-on-violation")
            .help("Attempt to cancel the current CI pipeline when policy violations are detected")
            .action(ArgAction::SetTrue),
        Arg::new("export_to_portal")
            .long("export-to-portal")
            .help("Export agentic action history to EDAMAME Portal")
            .env("EDAMAME_EXPORT_TO_PORTAL")
            .action(ArgAction::SetTrue),
        Arg::new("export_ai_failure_details")
            .long("export-ai-failure-details")
            .help("Force export of structured AI check failure details to Hub (Intune/managed fleets)")
            .env("EDAMAME_EXPORT_AI_FAILURE_DETAILS")
            .action(ArgAction::SetTrue),
    ]
}

fn disconnected_start_args() -> Vec<Arg> {
    vec![
        Arg::new("llm_api_key")
            .long("llm-api-key")
            .short('k')
            .value_name("API_KEY")
            .help("EDAMAME Portal LLM API key for the security assistant (edamame provider)")
            .env("EDAMAME_LLM_API_KEY")
            .value_parser(clap::value_parser!(String)),
        Arg::new("network_scan")
            .long("network-scan")
            .alias("lan-scan")
            .alias("lan-scanning")
            .short('n')
            .help("Enable LAN scanning and force LAN auto-scan on start")
            .action(ArgAction::SetTrue),
        Arg::new("packet_capture")
            .long("packet-capture")
            .alias("capture")
            .short('c')
            .help("Enable packet capture")
            .action(ArgAction::SetTrue),
        Arg::new("whitelist")
            .long("whitelist")
            .value_name("WHITELIST")
            .help("Whitelist name to enforce during capture")
            .value_parser(clap::value_parser!(String)),
        Arg::new("fail_on_whitelist")
            .long("fail-on-whitelist")
            .help("Treat whitelist violations as fatal (defaults to true when --whitelist is provided)")
            .action(ArgAction::SetTrue),
        Arg::new("fail_on_blacklist")
            .long("fail-on-blacklist")
            .help("Treat blacklist violations as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("fail_on_findings")
            .long("fail-on-findings")
            .help("Treat active attack pattern findings as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("include_local_traffic")
            .long("include-local-traffic")
            .alias("local-traffic")
            .help("Include local traffic in capture output")
            .action(ArgAction::SetTrue),
        Arg::new("agentic_mode")
            .long("agentic-mode")
            .value_name("MODE")
            .help("Security assistant mode for automated remediation: auto, analyze, off (turn the Assistant and both detection engines off) or disabled (leave them as last set)")
            .default_value("disabled")
            .value_parser(AGENTIC_MODES),
        Arg::new("agentic_provider")
            .long("agentic-provider")
            .value_name("PROVIDER")
            .help("LLM provider: edamame (Portal), claude, openai, ollama, none")
            .value_parser(["edamame", "claude", "openai", "ollama", "none"]),
        Arg::new("agentic_interval")
            .long("agentic-interval")
            .value_name("SECONDS")
            .help("Interval in seconds for automated todo processing (default: 3600)")
            .default_value("3600")
            .value_parser(clap::value_parser!(u64)),
        Arg::new("cancel_on_violation")
            .long("cancel-on-violation")
            .help("Attempt to cancel the current CI pipeline when policy violations are detected")
            .action(ArgAction::SetTrue),
        Arg::new("export_to_portal")
            .long("export-to-portal")
            .help("Export agentic action history to EDAMAME Portal")
            .env("EDAMAME_EXPORT_TO_PORTAL")
            .action(ArgAction::SetTrue),
        Arg::new("export_ai_failure_details")
            .long("export-ai-failure-details")
            .help("Force export of structured AI check failure details to Hub (Intune/managed fleets)")
            .env("EDAMAME_EXPORT_AI_FAILURE_DETAILS")
            .action(ArgAction::SetTrue),
    ]
}

#[cfg(test)]
mod tests {
    use super::build_cli;

    #[test]
    fn foreground_start_accepts_background_parameters() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "foreground-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
                "--device-id",
                "ci-node",
                "--network-scan",
                "--whitelist",
                "custom_whitelist",
                "--fail-on-whitelist",
                "--fail-on-blacklist",
                "--fail-on-findings",
                "--include-local-traffic",
                "--cancel-on-violation",
                "--agentic-mode",
                "auto",
                "--agentic-provider",
                "ollama",
                "--agentic-interval",
                "600",
            ])
            .expect("foreground-start should accept the same arguments as background-start");

        let (subcommand, sub_matches) = matches
            .subcommand()
            .expect("expected a subcommand for foreground-start");
        assert_eq!(subcommand, "foreground-start");

        assert_eq!(
            sub_matches.get_one::<String>("user").map(String::as_str),
            Some("runner")
        );
        assert_eq!(
            sub_matches.get_one::<String>("domain").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            sub_matches.get_one::<String>("pin").map(String::as_str),
            Some("123456")
        );
        assert_eq!(
            sub_matches
                .get_one::<String>("device_id")
                .map(String::as_str),
            Some("ci-node")
        );
        assert!(sub_matches.get_flag("network_scan"));
        assert!(sub_matches.get_flag("fail_on_whitelist"));
        assert!(sub_matches.get_flag("fail_on_blacklist"));
        assert!(sub_matches.get_flag("fail_on_findings"));
        assert!(sub_matches.get_flag("include_local_traffic"));
        assert!(sub_matches.get_flag("cancel_on_violation"));
        assert_eq!(
            sub_matches
                .get_one::<String>("whitelist")
                .map(String::as_str),
            Some("custom_whitelist")
        );
        assert_eq!(
            sub_matches
                .get_one::<String>("agentic_mode")
                .map(String::as_str),
            Some("auto")
        );
        assert_eq!(
            sub_matches
                .get_one::<String>("agentic_provider")
                .map(String::as_str),
            Some("ollama")
        );
        assert_eq!(sub_matches.get_one::<u64>("agentic_interval"), Some(&600));
    }

    #[test]
    fn accept_managed_config_is_opt_in_and_bare_means_always() {
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "edamame_posture",
                "background-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
            ];
            args.extend_from_slice(extra);
            let matches = build_cli()
                .try_get_matches_from(args)
                .expect("background-start parses");
            let (_, sub) = matches.subcommand().expect("subcommand");
            sub.get_one::<String>("accept_managed_config").cloned()
        };
        if std::env::var(super::ACCEPT_MANAGED_CONFIG_ENV).is_err() {
            assert_eq!(parse(&[]), None);
        }
        assert_eq!(
            parse(&["--accept-managed-config"]).as_deref(),
            Some("always")
        );
        assert_eq!(
            parse(&["--accept-managed-config", "sha256:abc"]).as_deref(),
            Some("sha256:abc")
        );
    }

    #[test]
    fn foreground_start_defaults_align_with_background() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "foreground-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
            ])
            .expect("foreground-start parsing with defaults");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected foreground-start subcommand");

        assert!(sub_matches.get_one::<String>("device_id").is_none());
        assert!(!sub_matches.get_flag("network_scan"));
        assert_eq!(sub_matches.get_one::<String>("whitelist"), None);
        assert!(!sub_matches.get_flag("fail_on_whitelist"));
        assert!(!sub_matches.get_flag("fail_on_blacklist"));
        assert!(!sub_matches.get_flag("fail_on_findings"));
        assert!(!sub_matches.get_flag("cancel_on_violation"));
        assert!(!sub_matches.get_flag("include_local_traffic"));
        assert_eq!(
            sub_matches
                .get_one::<String>("agentic_mode")
                .map(String::as_str),
            Some("disabled")
        );
        assert_eq!(sub_matches.get_one::<String>("agentic_provider"), None);
        assert_eq!(sub_matches.get_one::<u64>("agentic_interval"), Some(&3600));
    }

    #[test]
    fn foreground_start_accepts_api_key() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "foreground-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
                "--llm-api-key",
                "edm_live_test123abc",
            ])
            .expect("foreground-start should accept --llm-api-key");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected foreground-start subcommand");

        assert_eq!(
            sub_matches
                .get_one::<String>("llm_api_key")
                .map(String::as_str),
            Some("edm_live_test123abc")
        );
    }

    #[test]
    fn foreground_start_api_key_short_flag() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "foreground-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
                "-k",
                "edm_test_shortflag",
            ])
            .expect("foreground-start should accept -k short flag");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected foreground-start subcommand");

        assert_eq!(
            sub_matches
                .get_one::<String>("llm_api_key")
                .map(String::as_str),
            Some("edm_test_shortflag")
        );
    }

    #[test]
    fn foreground_start_api_key_is_optional() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "foreground-start",
                "--user",
                "runner",
                "--domain",
                "example.com",
                "--pin",
                "123456",
            ])
            .expect("foreground-start should work without --llm-api-key");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected foreground-start subcommand");

        let env_api_key = std::env::var("EDAMAME_LLM_API_KEY").ok();
        assert_eq!(
            sub_matches
                .get_one::<String>("llm_api_key")
                .map(String::as_str),
            env_api_key.as_deref()
        );
    }

    #[test]
    fn disconnected_start_accepts_api_key() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "background-start-disconnected",
                "--llm-api-key",
                "edm_live_disconnected123",
            ])
            .expect("background-start-disconnected should accept --llm-api-key");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected background-start-disconnected subcommand");

        assert_eq!(
            sub_matches
                .get_one::<String>("llm_api_key")
                .map(String::as_str),
            Some("edm_live_disconnected123")
        );
    }

    #[test]
    fn background_start_accepts_api_key() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "background-start",
                "--user",
                "testuser",
                "--domain",
                "test.example.com",
                "--pin",
                "000000",
                "--llm-api-key",
                "edm_live_background456",
            ])
            .expect("background-start should accept --llm-api-key");

        let (_, sub_matches) = matches
            .subcommand()
            .expect("expected background-start subcommand");

        assert_eq!(
            sub_matches
                .get_one::<String>("llm_api_key")
                .map(String::as_str),
            Some("edm_live_background456")
        );
    }

    /// Every enrollment-token source; reads and clears the process
    /// environment, so the cases run in one test.
    #[test]
    // Both tests set process-wide EDAMAME_PIN / EDAMAME_ENROLLMENT_TOKEN, which
    // every `start` parse reads: run them one at a time.
    #[serial_test::serial(process_env)]
    fn enrollment_token_sources_resolve_and_never_leak_through_the_environment() {
        use super::{resolve_enrollment_token, ENROLLMENT_TOKEN_ENV};
        const TOKEN: &str = "edm_enr_0123456789abcdef0123456789abcdef_secretpart";
        let parse = |args: &[&str]| {
            let matches = build_cli().try_get_matches_from(args).expect("parse");
            let (_, sub) = matches.subcommand().expect("subcommand");
            resolve_enrollment_token(sub)
        };
        let base = [
            "edamame_posture",
            "background-start",
            "--user",
            "alice",
            "--domain",
            "example.com",
        ];
        std::env::remove_var(ENROLLMENT_TOKEN_ENV);

        // None given.
        assert_eq!(parse(&base).unwrap(), "");

        // --enrollment-token (accepted, warned).
        let mut args = base.to_vec();
        args.extend(["--enrollment-token", TOKEN]);
        assert_eq!(parse(&args).unwrap(), TOKEN);

        // EDAMAME_ENROLLMENT_TOKEN: read, trimmed, then removed.
        std::env::set_var(ENROLLMENT_TOKEN_ENV, format!(" {TOKEN} "));
        assert_eq!(parse(&base).unwrap(), TOKEN);
        assert!(std::env::var(ENROLLMENT_TOKEN_ENV).is_err());

        // --enrollment-token-file: first line; conflicts with the flag.
        let dir = std::env::temp_dir().join(format!("posture-enroll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, format!("{TOKEN}\nignored\n")).unwrap();
        let file_arg = file.to_string_lossy().to_string();
        let mut args = base.to_vec();
        args.extend(["--enrollment-token-file", file_arg.as_str()]);
        assert_eq!(parse(&args).unwrap(), TOKEN);
        let mut args = base.to_vec();
        args.extend([
            "--enrollment-token-file",
            file_arg.as_str(),
            "--enrollment-token",
            TOKEN,
        ]);
        assert!(build_cli().try_get_matches_from(&args).is_err());
        std::fs::write(&file, "\n").unwrap();
        let mut args = base.to_vec();
        args.extend(["--enrollment-token-file", file_arg.as_str()]);
        assert!(parse(&args).is_err());
        let _ = std::fs::remove_dir_all(&dir);

        // Accepted on foreground-start too; the token never shows in help.
        let fg = [
            "edamame_posture",
            "foreground-start",
            "--user",
            "alice",
            "--domain",
            "example.com",
            "--enrollment-token",
            TOKEN,
        ];
        assert!(build_cli().try_get_matches_from(fg).is_ok());
    }

    /// One test for every PIN source: resolve_pin reads and clears the
    /// process environment, so the cases must not run in parallel.
    #[test]
    // Both tests set process-wide EDAMAME_PIN / EDAMAME_ENROLLMENT_TOKEN, which
    // every `start` parse reads: run them one at a time.
    #[serial_test::serial(process_env)]
    fn pin_sources_resolve_in_order_and_never_leak_through_the_environment() {
        use super::{resolve_pin, PinSource};
        let parse = |args: &[&str]| {
            let matches = build_cli().try_get_matches_from(args).expect("parse");
            let (_, sub) = matches.subcommand().expect("subcommand");
            resolve_pin(sub)
        };
        let base = [
            "edamame_posture",
            "foreground-start",
            "--user",
            "runner",
            "--domain",
            "example.com",
        ];

        // --pin: accepted (compatibility), flagged as command line.
        let mut args = base.to_vec();
        args.extend(["--pin", "123456"]);
        assert_eq!(
            parse(&args).unwrap(),
            ("123456".to_string(), PinSource::CommandLine)
        );

        // EDAMAME_PIN: read, then removed from the environment.
        std::env::set_var("EDAMAME_PIN", "654321");
        assert_eq!(
            parse(&base).unwrap(),
            ("654321".to_string(), PinSource::Environment)
        );
        assert!(
            std::env::var("EDAMAME_PIN").is_err(),
            "EDAMAME_PIN left in the environment"
        );

        // A non-digit PIN from the environment is rejected like one on argv.
        std::env::set_var("EDAMAME_PIN", "12ab");
        assert!(build_cli().try_get_matches_from(base).is_err());
        std::env::remove_var("EDAMAME_PIN");

        // --pin-file: first line, trimmed.
        let dir = std::env::temp_dir().join(format!("posture-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("pin");
        std::fs::write(&file, "  777888 \nignored\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let file_arg = file.to_string_lossy().to_string();
        let mut args = base.to_vec();
        args.extend(["--pin-file", file_arg.as_str()]);
        assert_eq!(
            parse(&args).unwrap(),
            ("777888".to_string(), PinSource::File)
        );

        // --pin-file and --pin conflict; a bad file is an error.
        let mut args = base.to_vec();
        args.extend(["--pin-file", file_arg.as_str(), "--pin", "1"]);
        assert!(build_cli().try_get_matches_from(&args).is_err());
        std::fs::write(&file, "not-a-pin\n").unwrap();
        let mut args = base.to_vec();
        args.extend(["--pin-file", file_arg.as_str()]);
        assert!(parse(&args).is_err());
        let missing = dir.join("missing").to_string_lossy().to_string();
        let mut args = base.to_vec();
        args.extend(["--pin-file", missing.as_str()]);
        assert!(parse(&args).is_err());

        // No PIN at all: disconnected-style empty.
        assert_eq!(parse(&base).unwrap(), (String::new(), PinSource::None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agentic_mode_off_is_accepted_everywhere() {
        for sub in [
            "foreground-start",
            "background-start",
            "background-start-disconnected",
        ] {
            let matches = build_cli()
                .try_get_matches_from(["edamame_posture", sub, "--agentic-mode", "off"])
                .unwrap_or_else(|e| panic!("{sub}: {e}"));
            let (_, sub_matches) = matches.subcommand().unwrap();
            assert_eq!(
                sub_matches
                    .get_one::<String>("agentic_mode")
                    .map(String::as_str),
                Some("off")
            );
        }
    }

    #[test]
    fn start_file_monitor_parses_with_paths() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "background-start-file-monitor",
                "--paths",
                "/home/user/.ssh,/etc/shadow",
            ])
            .expect("background-start-file-monitor should accept --paths");

        let (sub, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-start-file-monitor");
        assert_eq!(
            sub_matches.get_one::<String>("paths").map(String::as_str),
            Some("/home/user/.ssh,/etc/shadow")
        );
    }

    #[test]
    fn start_file_monitor_parses_without_paths() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "background-start-file-monitor"])
            .expect("background-start-file-monitor should work without --paths");

        let (sub, _) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-start-file-monitor");
    }

    #[test]
    fn stop_file_monitor_parses() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "background-stop-file-monitor"])
            .expect("background-stop-file-monitor should parse");

        let (sub, _) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-stop-file-monitor");
    }

    #[test]
    fn file_monitor_status_parses() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "background-file-monitor-status"])
            .expect("background-file-monitor-status should parse");

        let (sub, _) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-file-monitor-status");
    }

    #[test]
    fn get_file_events_parses_with_fail_flag() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "background-get-file-events",
                "--fail-on-suspicious",
            ])
            .expect("background-get-file-events should accept --fail-on-suspicious");

        let (sub, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-get-file-events");
        assert!(sub_matches.get_flag("fail-on-suspicious"));
    }

    #[test]
    fn get_file_events_parses_without_fail_flag() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "background-get-file-events"])
            .expect("background-get-file-events should work without --fail-on-suspicious");

        let (sub, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-get-file-events");
        assert!(!sub_matches.get_flag("fail-on-suspicious"));
    }

    #[test]
    fn vulnerability_status_parses_with_fail_flag() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "background-attack-pattern-status",
                "--fail-on-findings",
            ])
            .expect("background-vulnerability-status should accept --fail-on-findings");

        let (sub, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-attack-pattern-status");
        assert!(sub_matches.get_flag("fail-on-findings"));
    }

    #[test]
    fn vulnerability_status_alias_parses_without_fail_flag() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "vulnerability-status"])
            .expect("vulnerability-status alias should parse");

        let (sub, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-attack-pattern-status");
        assert!(!sub_matches.get_flag("fail-on-findings"));
        assert_eq!(sub_matches.get_one::<String>("since"), None);
    }

    #[test]
    fn vulnerability_status_since_scopes_the_fail_flag_only() {
        let matches = build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "vulnerability-status",
                "--fail-on-findings",
                "--since",
                "2026-09-29T08:00:00Z",
            ])
            .expect("vulnerability-status should accept --since with --fail-on-findings");
        let (_, sub_matches) = matches.subcommand().expect("expected subcommand");
        assert_eq!(
            sub_matches.get_one::<String>("since").map(String::as_str),
            Some("2026-09-29T08:00:00Z")
        );

        // A scope without a gate means nothing.
        assert!(build_cli()
            .try_get_matches_from([
                "edamame_posture",
                "attack-pattern-status",
                "--since",
                "2026-09-29T08:00:00Z",
            ])
            .is_err());
    }

    #[test]
    fn clear_file_events_parses() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "background-clear-file-events"])
            .expect("background-clear-file-events should parse");

        let (sub, _) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-clear-file-events");
    }

    #[test]
    fn start_file_monitor_aliases_parse() {
        let matches = build_cli()
            .try_get_matches_from(["edamame_posture", "start-file-monitor"])
            .expect("start-file-monitor alias should parse");

        let (sub, _) = matches.subcommand().expect("expected subcommand");
        assert_eq!(sub, "background-start-file-monitor");
    }
}
