use crate::parse_digits_only;
use crate::parse_email;
use crate::parse_fqdn;
use crate::parse_signature;
use crate::parse_username;
use crate::CORE_VERSION;
use clap::{arg, ArgAction, Command};
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
                arg!([ZEEK_FORMAT] "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([LOCAL_TRAFFIC] "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([CHECK_WHITELIST] "Exit with code 1 if any whitelist exception is detected")
                    .required(false)
                    .default_value("true")
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([CHECK_BLACKLIST] "Exit with code 1 if blacklisted sessions are detected")
                    .required(false)
                    .default_value("true")
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([CHECK_ANOMALOUS] "Exit with code 1 if anomalous sessions are detected")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
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
            .arg(
                arg!(<USER> "User name")
                    .required(true)
                    // Throw an error if the string is an email address
                    .value_parser(parse_username)
            )
            .arg(
                arg!(<DOMAIN> "Domain name")
                    .required(true)
                    // FQDN only
                    .value_parser(parse_fqdn),
            )
            .arg(
                arg!(<PIN> "PIN")
                    .required(true)
                    // String with digits only
                    .value_parser(parse_digits_only),
            )
            .arg(
                arg!([AGENTIC_MODE] "AI assistant mode: auto, semi, manual, or disabled")
                    .required(false)
                    .default_value("disabled")
                    .value_parser(["auto", "semi", "manual", "disabled"]),
            )
            .arg(
                arg!([AGENTIC_PROVIDER] "LLM provider: claude, openai, ollama, none")
                    .required(false)
                    .value_parser(["claude", "openai", "ollama", "none"]),
            )
            .arg(
                arg!([AGENTIC_INTERVAL] "Interval in seconds for automated todo processing (default: 300)")
                    .required(false)
                    .default_value("300")
                    .value_parser(clap::value_parser!(u64)),
            )
    )
    .subcommand(
        Command::new("background-start")
            .alias("start")
            .about("Start reporting background process")
            .arg(
                arg!(<USER> "User name")
                    .required(true)
                    .value_parser(parse_username),
            )
            .arg(
                arg!(<DOMAIN> "Domain name")
                    .required(true)
                    // FQDN only
                    .value_parser(parse_fqdn),
            )
            .arg(
                arg!(<PIN> "PIN")
                    .required(true)
                    // String with digits only
                    .value_parser(parse_digits_only),
            )
            .arg(
                arg!([DEVICE_ID] "Device ID in the form of a string, this will be used as a suffix to the detected hardware ID. When non empty, the endpoint will be flagged as a CI/CD runner.")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([LAN_SCANNING] "LAN scanning enabled")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([WHITELIST_NAME] "Whitelist name")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([LOCAL_TRAFFIC] "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([AGENTIC_MODE] "AI assistant mode for automated todo processing: auto, semi, manual, or disabled")
                    .required(false)
                    .default_value("disabled")
                    .value_parser(["auto", "semi", "manual", "disabled"]),
            )
            .arg(
                arg!([AGENTIC_PROVIDER] "LLM provider for AI assistant: claude, openai, ollama, none")
                    .required(false)
                    .value_parser(["claude", "openai", "ollama", "none"]),
            )
            .arg(
                arg!([AGENTIC_INTERVAL] "Interval in seconds for automated todo processing (default: 300)")
                    .required(false)
                    .default_value("300")
                    .value_parser(clap::value_parser!(u64)),
            )
    )
    .subcommand(Command::new("background-stop").alias("stop").about("Stop reporting background process"))
    .subcommand(Command::new("background-status").alias("status").about("Get status of reporting background process"))
    .subcommand(Command::new("background-last-report-signature").alias("get-last-report-signature").about("Get last report signature of background process"))
    .subcommand(Command::new("background-get-history").alias("get-history").about("Get history of score modifications"))
    .subcommand(
        Command::new("background-start-disconnected")
            .about("Start the background process in disconnected mode (without domain authentication)")
            .arg(
                arg!([LAN_SCANNING] "LAN scanning enabled")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!([WHITELIST_NAME] "Whitelist name")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!([LOCAL_TRAFFIC] "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            )
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
}
