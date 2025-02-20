use crate::parse_digits_only;
use crate::parse_email;
use crate::parse_fqdn;
use crate::parse_signature;
use crate::parse_username;
use crate::CORE_VERSION;
use clap::{arg, ArgAction, Command};
use clap_complete::Shell;

pub fn build_cli() -> Command {
    let core_version_runtime: String = CORE_VERSION.to_string();
    let core_version_static: &'static str = Box::leak(core_version_runtime.into_boxed_str());

    Command::new("edamame_posture")
        .version(core_version_static)
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
    // Add completion subcommand
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
    .subcommand(Command::new("score").about("Get score information"))
    .subcommand(Command::new("lanscan").about("Performs a LAN scan"))
    .subcommand(
        Command::new("capture")
            .about("Capture packets")
            .arg(
                arg!(<SECONDS> "Number of seconds to capture")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            )
            // Required whitelist name
            .arg(
                arg!(<WHITELIST_NAME> "Whitelist name")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            // Optional Zeek format
            .arg(
                arg!(<ZEEK_FORMAT> "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!(<LOCAL_TRAFFIC> "Include local traffic")
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
        Command::new("remediate").about("Remediate threats").arg(
            arg!(<REMEDIATIONS> "Remediations to skip (comma separated list), by default only remote login enabled is skipped")
                .required(false)
                .default_value("remote login enabled"),
        ),
    )
    .subcommand(Command::new("request-signature").about("Report the security posture anonymously and get a signature for later retrieval"))
    .subcommand(Command::new("request-report").about("Send a report from a signature to an email address").arg(
        arg!(<EMAIL> "Email address")
                .required(true)
                .value_parser(parse_email)).arg(
            arg!(<SIGNATURE> "Signature")
                .required(true)
                .value_parser(parse_signature),
        ),
    )
    //////////////////////
    // Background commands
    //////////////////////
    .subcommand(Command::new("background-logs").alias("logs").about("Display logs from the background process"))
    .subcommand(
        Command::new("background-wait-for-connection")
            .alias("wait-for-connection")
            .about("Wait for connection of the background process")
            .arg(
                arg!(<TIMEOUT> "Timeout in seconds")
                    .required(false)
                    .value_parser(clap::value_parser!(u64)),
            ),
    )
    .subcommand(
        Command::new("background-sessions")
            .alias("get-sessions")
            .about("Get connections of the background process")
            .arg(
                arg!(<ZEEK_FORMAT> "Zeek format")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!(<LOCAL_TRAFFIC> "Include local traffic")
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
                arg!(<LAN_SCANNING> "LAN scanning enabled")
                    .required(false)
                    .value_parser(clap::value_parser!(bool)),
            )
            .arg(
                arg!(<WHITELIST_NAME> "Whitelist name")
                    .required(false)
                    .value_parser(clap::value_parser!(String)),
            )
            .arg(
                arg!(<LOCAL_TRAFFIC> "Include local traffic")
                    .required(false)
                    .default_value("false")
                    .value_parser(clap::value_parser!(bool)),
            )
    )
    .subcommand(Command::new("background-stop").alias("stop").about("Stop reporting background process"))
    .subcommand(Command::new("background-status").alias("status").about("Get status of reporting background process"))
    .subcommand(Command::new("background-last-report-signature").alias("get-last-report-signature").about("Get last report signature of background process"))
    .subcommand(Command::new("background-get-history").alias("get-history").about("Get history of score modifications"))
}
