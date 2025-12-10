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
    )
    .subcommand(Command::new("background-mcp-stop").alias("mcp-stop").about("Stop MCP server"))
    .subcommand(Command::new("background-mcp-status").alias("mcp-status").about("Get MCP server status"))
    .subcommand(Command::new("background-mcp-generate-psk").alias("mcp-generate-psk").about("Generate a secure PSK for MCP server"))
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
            .help("PIN")
            .value_parser(parse_digits_only)
            .default_value(""),
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
            .help("Enable LAN scanning")
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
        Arg::new("fail_on_anomalous")
            .long("fail-on-anomalous")
            .help("Treat anomalous sessions as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("include_local_traffic")
            .long("include-local-traffic")
            .alias("local-traffic")
            .help("Include local traffic in capture output")
            .action(ArgAction::SetTrue),
        Arg::new("agentic_mode")
            .long("agentic-mode")
            .value_name("MODE")
            .help("AI assistant mode: auto, analyze or disabled")
            .default_value("disabled")
            .value_parser(["auto", "analyze", "disabled"]),
        Arg::new("agentic_provider")
            .long("agentic-provider")
            .value_name("PROVIDER")
            .help("LLM provider: claude, openai, ollama, none")
            .value_parser(["claude", "openai", "ollama", "none"]),
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
    ]
}

fn disconnected_start_args() -> Vec<Arg> {
    vec![
        Arg::new("network_scan")
            .long("network-scan")
            .alias("lan-scan")
            .alias("lan-scanning")
            .short('n')
            .help("Enable LAN scanning")
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
        Arg::new("fail_on_anomalous")
            .long("fail-on-anomalous")
            .help("Treat anomalous sessions as fatal")
            .action(ArgAction::SetTrue),
        Arg::new("include_local_traffic")
            .long("include-local-traffic")
            .alias("local-traffic")
            .help("Include local traffic in capture output")
            .action(ArgAction::SetTrue),
        Arg::new("agentic_mode")
            .long("agentic-mode")
            .value_name("MODE")
            .help("AI assistant mode for automated todo processing: auto, analyze or disabled")
            .default_value("disabled")
            .value_parser(["auto", "analyze", "disabled"]),
        Arg::new("cancel_on_violation")
            .long("cancel-on-violation")
            .help("Attempt to cancel the current CI pipeline when policy violations are detected")
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
                "--fail-on-anomalous",
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
        assert!(sub_matches.get_flag("fail_on_anomalous"));
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
        assert!(!sub_matches.get_flag("fail_on_anomalous"));
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
}
