use crate::base::*;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::ERROR_CODE_MISMATCH;
use crate::ERROR_CODE_PARAM;
use crate::ERROR_CODE_SERVER_ERROR;
use crate::ERROR_CODE_TIMEOUT;
use edamame_core::api::api_agentic::*;
use edamame_core::api::api_core::*;
use edamame_core::api::api_flodbadd::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_history::*;
use edamame_core::api::api_score_threats::*;
use edamame_core::api::api_trust::*;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, info, warn};

pub fn background_get_sessions(
    zeek_format: bool,
    local_traffic: bool,
    fail_on_anomalous: bool,
    fail_on_blacklist: bool,
    fail_on_whitelisted: bool,
) -> i32 {
    let sessions = match rpc_get_lan_sessions(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting LAN sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    // Filter and display sessions (normal mode)
    background_display_sessions(sessions.sessions, zeek_format, local_traffic, false);

    // Determine exit code based on checks
    let mut exit_code = 0;

    // Always check whitelist conformance
    if fail_on_whitelisted {
        let whitelist_conformance = match rpc_get_whitelist_conformance(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(conformance) => conformance,
            Err(e) => {
                eprintln!("Error getting whitelist conformance: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };

        if !whitelist_conformance {
            eprintln!("Non-conforming sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    // Check for anomalous sessions if requested
    if fail_on_anomalous {
        let anomalous_status = match rpc_get_anomalous_status(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error checking anomalous session status: {}", e);
                false
            }
        };

        if anomalous_status {
            eprintln!("Anomalous sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    // Check for blacklisted sessions if requested
    if fail_on_blacklist {
        let blacklisted_status = match rpc_get_blacklisted_status(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error checking blacklisted session status: {}", e);
                false
            }
        };

        if blacklisted_status {
            eprintln!("Blacklisted sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    return exit_code;
}

pub fn background_display_sessions(
    sessions: Vec<SessionInfoAPI>,
    zeek_format: bool,
    local_traffic: bool,
    exceptions_only: bool,
) {
    // Get all sessions first
    let mut filtered_sessions = sessions;

    // If we only want exceptions, find the exceptions
    if exceptions_only {
        // Extract the sessions with status that aren't "Conforming"
        filtered_sessions = filtered_sessions
            .into_iter()
            .filter(|session| {
                session.is_whitelisted
                    != edamame_core::api::api_flodbadd::WhiteListStateAPI::Conforming
            })
            .collect::<Vec<_>>();
    }

    // Filter out local traffic if requested
    if !local_traffic {
        filtered_sessions = filter_global_sessions(filtered_sessions);
    }

    // Format the connections and display them
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(filtered_sessions)
    } else {
        format_sessions_log(filtered_sessions)
    };

    // Display the sessions
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }
}

pub fn background_get_exceptions(zeek_format: bool, local_traffic: bool) -> i32 {
    let sessions = match rpc_get_lan_sessions(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting LAN sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    // Display only exceptions
    background_display_sessions(sessions.sessions, zeek_format, local_traffic, true);

    return 0;
}

pub fn background_get_threats_info() -> i32 {
    match rpc_get_score(
        false,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(score) => {
            println!(
                "Threat model name: {}, date: {}, signature: {}",
                score.model_name, score.model_date, score.model_signature
            );
            0
        }
        Err(e) => {
            eprintln!("Error getting threats info: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_get_status() -> i32 {
    match rpc_get_connection(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            println!("Connection status:");
            println!("{}", status);
            0
        }
        Err(e) => {
            eprintln!("Error getting connection status: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_get_last_report_signature() -> i32 {
    let signature = match rpc_get_last_report_signature(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("Error getting last reported signature: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };
    println!("{}", signature);
    0
}

pub fn background_get_device_info() -> i32 {
    let info = match rpc_get_device_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error getting device information: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };
    println!("Device information from the background process:");
    println!("{}", info);
    0
}

pub fn background_wait_for_connection(timeout: u64) -> i32 {
    // Display device and system info
    background_get_device_info();
    base_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;

    let mut connection_status = ConnectionStatusAPI {
        connected_domain: "".to_string(),
        connected_user: "".to_string(),
        pin: "".to_string(),
        is_success: false,
        is_connected: false,
        is_success_pin: false,
        is_outdated_backend: false,
        is_outdated_threats: false,
        last_network_activity: "".to_string(),
        last_report_time: "".to_string(),
        last_report_signature: "".to_string(),
        backend_error_code: "".to_string(),
        backend_error_reason: "".to_string(),
    };

    // Wait until the daemon reports that it is connected, or until we time out
    while !connection_status.is_connected && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;

        connection_status = match rpc_get_connection(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error getting connection status: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };

        // The backend error code won't reflect an actual error until communication with the backend occur, i.e. the connection is established
        if connection_status.is_connected && connection_status.backend_error_code != "None" {
            eprintln!(
                "Error attempting to connect to domain: {}, {}",
                connection_status.backend_error_code, connection_status.backend_error_reason
            );
            return ERROR_CODE_PARAM;
        }

        println!(
            "Waiting for score computation and reporting to complete... (connected: {}, network activity: {}, report signature: {})",
            connection_status.is_connected,
            connection_status.last_network_activity,
            connection_status.last_report_signature
        );
    }

    if timeout == 0 || !connection_status.is_connected {
        eprintln!("Timeout waiting for background process to connect to domain...");
        return ERROR_CODE_TIMEOUT;
    } else {
        println!(
            "Connection successful with domain {} and user {} (connected: {}, network activity: {})",
            connection_status.connected_domain,
            connection_status.connected_user,
            connection_status.is_connected,
            connection_status.last_network_activity
        );

        // Print the score results
        let score = match rpc_get_score(
            false,
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(score) => score,
            Err(e) => {
                eprintln!("Error getting score: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };
        let url = get_threats_url().to_string();
        // Pretty print the final score with important details
        println!("Security Score summary:");
        println!("{}", score);
        println!("Model URL: {}", url);

        // Print the lanscan results
        let devices = match rpc_get_lanscan(
            false,
            false,
            false,
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(devices) => devices,
            Err(e) => {
                eprintln!("Error getting LAN devices: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };
        println!("LAN scan completed at: {}", devices.last_scan);
        println!("{}", devices);
    }
    0
}

pub fn background_stop() -> i32 {
    match rpc_terminate(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error terminating background process: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
    0
}

pub fn background_get_history() -> i32 {
    match rpc_get_history(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(history) => {
            println!("History: {:#?}", history);
            0
        }
        Err(e) => {
            eprintln!("Error getting history: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_create_custom_whitelists_with_list() -> (String, i32) {
    match rpc_create_custom_whitelists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            if whitelists.is_empty() {
                eprintln!("Failed to create custom whitelists");
                return (String::new(), ERROR_CODE_SERVER_ERROR);
            } else {
                // The whitelist is a String represent a JSON object
                // We need to parse it and print it pretty
                let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Error parsing whitelist JSON: {}", e);
                        return (String::new(), ERROR_CODE_SERVER_ERROR);
                    }
                };
                let pretty_json = match serde_json::to_string_pretty(&json_value) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Error formatting whitelist JSON: {}", e);
                        return (String::new(), ERROR_CODE_SERVER_ERROR);
                    }
                };
                println!("{}", pretty_json);
                return (pretty_json, 0);
            }
        }
        Err(e) => {
            eprintln!("Error creating custom whitelists: {}", e);
            return (String::new(), ERROR_CODE_SERVER_ERROR);
        }
    }
}

pub fn background_create_custom_whitelists() -> i32 {
    let (_, exit_code) = background_create_custom_whitelists_with_list();
    exit_code
}

/// Create custom whitelists with process information included.
/// This provides stricter matching (connections must come from the same process).
pub fn background_create_custom_whitelists_with_process() -> i32 {
    match rpc_create_custom_whitelists_with_process(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            if whitelists.is_empty() {
                eprintln!("Failed to create custom whitelists with process");
                return ERROR_CODE_SERVER_ERROR;
            } else {
                let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Error parsing whitelist JSON: {}", e);
                        return ERROR_CODE_SERVER_ERROR;
                    }
                };
                let pretty_json = match serde_json::to_string_pretty(&json_value) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Error formatting whitelist JSON: {}", e);
                        return ERROR_CODE_SERVER_ERROR;
                    }
                };
                println!("{}", pretty_json);
                return 0;
            }
        }
        Err(e) => {
            eprintln!("Error creating custom whitelists with process: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_set_custom_whitelists(whitelist_json: String) -> i32 {
    match rpc_set_custom_whitelists(
        whitelist_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error setting custom whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_create_and_set_custom_whitelists() -> i32 {
    let (whitelist_json, exit_code) = background_create_custom_whitelists_with_list();
    if exit_code != 0 {
        return exit_code;
    }
    background_set_custom_whitelists(whitelist_json)
}

pub fn background_get_score() -> i32 {
    match rpc_get_score(
        false,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(score) => {
            println!("Security Score summary:");
            println!("{}", score);

            // Get threats URL
            match rpc_get_threats_url(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(url) => println!("Model URL: {}", url),
                Err(_) => (), // Ignore error if we can't get the URL
            }
            0
        }
        Err(e) => {
            eprintln!("Error getting score: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to display anomalous sessions
pub fn background_get_anomalous_sessions(zeek_format: bool) -> i32 {
    // Get anomalous sessions
    let anomalous_sessions = match rpc_get_anomalous_sessions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting anomalous sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    if anomalous_sessions.is_empty() {
        return 0;
    }

    // Format and display sessions
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(anomalous_sessions)
    } else {
        format_sessions_log(anomalous_sessions)
    };
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }

    return 0; // Always return 0 on success, even if sessions are found
}

// Function to display blacklisted sessions
pub fn background_get_blacklisted_sessions(zeek_format: bool) -> i32 {
    // Get blacklisted sessions
    let blacklisted_sessions = match rpc_get_blacklisted_sessions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting blacklisted sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    if blacklisted_sessions.is_empty() {
        return 0;
    }

    // Format and display sessions
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(blacklisted_sessions)
    } else {
        format_sessions_log(blacklisted_sessions)
    };
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }

    return 0; // Always return 0 on success, even if sessions are found
}

pub fn background_set_custom_blacklists(blacklist_json: String) -> i32 {
    match rpc_set_custom_blacklists(
        blacklist_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            println!("Custom blacklists set successfully.");
            0
        }
        Err(e) => {
            eprintln!("Error setting custom blacklists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve blacklists
pub fn background_get_blacklists() -> i32 {
    match rpc_get_blacklists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(blacklists) => {
            // The list is a String represent a JSON object
            // We need to parse it and print it pretty
            let json_value: serde_json::Value = match serde_json::from_str(&blacklists) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error parsing blacklist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            let pretty_json = match serde_json::to_string_pretty(&json_value) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error formatting blacklist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            println!("{}", pretty_json);
            0
        }
        Err(e) => {
            eprintln!("Error getting blacklists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve whitelists
pub fn background_get_whitelists() -> i32 {
    match rpc_get_whitelists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            // The list is a String represent a JSON object
            // We need to parse it and print it pretty
            let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error parsing whitelist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            let pretty_json = match serde_json::to_string_pretty(&json_value) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error formatting whitelist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            println!("{}", pretty_json);
            0
        }
        Err(e) => {
            eprintln!("Error getting whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve whitelist name
pub fn background_get_whitelist_name() -> i32 {
    match rpc_get_whitelist_name(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(name) => {
            println!("{}", name);
            0
        }
        Err(e) => {
            eprintln!("Error getting whitelist name: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to augment custom whitelists from the background process
pub fn background_augment_custom_whitelists() -> i32 {
    match rpc_augment_custom_whitelists_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok((whitelist_json, percent_changed)) => {
            if whitelist_json.is_empty() {
                eprintln!("Failed to augment custom whitelists");
                return ERROR_CODE_SERVER_ERROR;
            }

            // Informational: report % of changes to stderr so stdout remains JSON-only
            eprintln!("Percent of changes: {:.2}", percent_changed);

            match serde_json::from_str::<serde_json::Value>(&whitelist_json) {
                Ok(json_value) => {
                    match serde_json::to_string_pretty(&json_value) {
                        Ok(pretty_json) => println!("{}", pretty_json),
                        Err(_) => println!("{}", whitelist_json),
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error parsing augmented whitelist JSON: {}", e);
                    ERROR_CODE_PARAM
                }
            }
        }
        Err(e) => {
            eprintln!("Error augmenting custom whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Configure agentic LLM provider for background process
#[allow(unused_variables)]
pub fn background_configure_agentic(provider: String) {
    use edamame_core::api::api_agentic::*;

    info!("Configuring AI Assistant provider: {}", provider);

    // Unified API key handling through EDAMAME_LLM_API_KEY for all providers
    let api_key = std::env::var("EDAMAME_LLM_API_KEY").unwrap_or_default();

    // Handle EDAMAME Portal LLM
    if provider == "edamame" {
        if api_key.is_empty() {
            error!("EDAMAME_LLM_API_KEY environment variable is required for provider 'edamame'");
            error!("Get your API key at https://portal.edamame.tech/api-keys");
            return;
        }

        if !api_key.starts_with("edm_") && !api_key.starts_with("edak_") {
            warn!("EDAMAME Portal API key should start with 'edm_' or 'edak_' prefix");
        }

        // Set the EDAMAME API key for headless authentication
        if agentic_set_edamame_api_key(api_key) {
            info!("AI Assistant configured with EDAMAME Portal LLM");
        } else {
            error!("Failed to set EDAMAME API key");
        }
        return;
    }

    // Handle BYOLLM providers (claude, openai, ollama)
    let model = std::env::var("EDAMAME_LLM_MODEL").unwrap_or_else(|_| {
        match provider.as_str() {
            "claude" => "claude-4-5-haiku".to_string(), // Use Haiku for background (faster/cheaper)
            "openai" => "gpt-5-mini-2025-08-07".to_string(),
            "ollama" => "llama4".to_string(),
            _ => String::new(),
        }
    });
    let base_url = std::env::var("EDAMAME_LLM_BASE_URL").unwrap_or_default();
    let slack_bot_token = std::env::var("EDAMAME_AGENTIC_SLACK_BOT_TOKEN")
        .or_else(|_| std::env::var("EDAMAME_AGENTIC_WEBHOOK_ACTIONS_TOKEN"))
        .unwrap_or_default();
    let slack_actions_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL").unwrap_or_default();
    let slack_escalations_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL").unwrap_or_default();

    // Legacy webhook environment variables are deprecated but we still surface a warning
    let legacy_actions_url =
        std::env::var("EDAMAME_AGENTIC_WEBHOOK_ACTIONS_URL").unwrap_or_default();
    let legacy_escalations_url =
        std::env::var("EDAMAME_AGENTIC_WEBHOOK_ESCALATIONS_URL").unwrap_or_default();

    if !legacy_actions_url.is_empty() || !legacy_escalations_url.is_empty() {
        warn!(
            "EDAMAME_AGENTIC_WEBHOOK_* environment variables are deprecated – use EDAMAME_AGENTIC_SLACK_* instead"
        );
    }

    // MCP PSK not needed for background mode (no external AI clients)
    let mcp_psk = String::new();

    if slack_bot_token.is_empty()
        && (!slack_actions_channel.is_empty() || !slack_escalations_channel.is_empty())
    {
        warn!("Slack notifications requested but EDAMAME_AGENTIC_SLACK_BOT_TOKEN is missing");
    }

    if !slack_actions_channel.is_empty() {
        info!(
            "AI Assistant Slack actions channel configured: {}",
            slack_actions_channel
        );
    }

    if !slack_escalations_channel.is_empty() {
        info!(
            "AI Assistant Slack escalations channel configured: {}",
            slack_escalations_channel
        );
    }

    if agentic_set_llm_config(
        provider.clone(),
        api_key.clone(),
        model.clone(),
        base_url,
        mcp_psk,
        slack_bot_token,
        slack_actions_channel,
        slack_escalations_channel,
    ) {
        info!("AI Assistant configured: {} / {}", provider, model);
    } else {
        error!("Failed to configure AI Assistant. Check EDAMAME_LLM_API_KEY environment variable.");
    }
}

// ============================================================================
// MCP Server Control (for headless/daemon mode)
// ============================================================================

pub fn background_mcp_generate_psk() -> i32 {
    let psk = mcp_generate_psk();
    println!("{}", psk);
    println!("# Save this PSK securely - it's required for MCP client authentication");
    0
}

pub fn background_mcp_start(port: u16, psk: Option<String>, all_interfaces: bool) -> i32 {
    use edamame_core::api::api_agentic::mcp_start_server;

    // Use provided PSK or generate new one
    let actual_psk = psk.unwrap_or_else(|| {
        let generated = mcp_generate_psk();
        println!("# Generated new PSK: {}", generated);
        println!("# Save this PSK - you'll need it to connect MCP clients");
        generated
    });

    if actual_psk.len() < 32 {
        eprintln!("Error: PSK must be at least 32 characters");
        eprintln!("Generate one with: edamame_posture mcp-generate-psk");
        return ERROR_CODE_PARAM;
    }

    match mcp_start_server(port, actual_psk.clone(), false, all_interfaces) {
        result => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                let bind_addr = if all_interfaces {
                    "<your-ip-address>"
                } else {
                    "127.0.0.1"
                };
                println!("[OK] MCP server started successfully");
                println!("   Port: {}", json["port"]);
                println!("   URL: {}", json["url"].as_str().unwrap_or(""));
                println!("   PSK: {}", actual_psk);
                if all_interfaces {
                    println!("\n[WARN] Warning: Server is listening on ALL network interfaces");
                    println!(
                        "   Accessible from your local network - ensure your network is secure!"
                    );
                }
                println!("\nClaude Desktop config:");
                println!(
                    r#"{{
  "mcpServers": {{
    "edamame": {{
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://{}:{}/mcp",
        "--header",
        "Authorization: Bearer {}"
      ]
    }}
  }}
}}"#,
                    bind_addr, port, actual_psk
                );
                0
            } else {
                eprintln!(
                    "Failed to start MCP server: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
    }
}

pub fn background_mcp_stop() -> i32 {
    use edamame_core::api::api_agentic::mcp_stop_server;

    match mcp_stop_server() {
        result => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("[OK] MCP server stopped");
                0
            } else {
                eprintln!(
                    "Failed to stop MCP server: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
    }
}

pub fn background_mcp_status() -> i32 {
    use edamame_core::api::api_agentic::mcp_get_server_status;

    match mcp_get_server_status() {
        result => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["running"].as_bool().unwrap_or(false) {
                println!("[OK] MCP server is running");
                println!("   Port: {}", json["port"]);
                println!("   URL: {}", json["url"].as_str().unwrap_or(""));
            } else {
                println!("○ MCP server is not running");
            }
            0
        }
    }
}

pub fn background_agentic_summary() -> i32 {
    use edamame_core::api::api_agentic::agentic_get_summary;

    let summary = agentic_get_summary();

    println!("================================================================");
    println!("                    AGENTIC STATUS SUMMARY                      ");
    println!("================================================================");

    // LLM Provider
    println!("\n[LLM Provider]");
    println!("  Provider: {}", summary.provider);
    // For internal provider, model is managed by EDAMAME backend
    let model_display = if summary.model.is_empty() {
        if summary.provider == "internal" {
            "managed by backend"
        } else {
            "default"
        }
    } else {
        &summary.model
    };
    println!("  Model: {}", model_display);
    println!(
        "  API Key: {}",
        if summary.has_api_key {
            "configured"
        } else {
            "not set"
        }
    );
    println!("  Tested: {}", if summary.tested { "yes" } else { "no" });

    // Auto Processing
    println!("\n[Auto Processing]");
    println!(
        "  Enabled: {}",
        if summary.auto_processing_enabled {
            "yes"
        } else {
            "no"
        }
    );
    println!("  Mode: {}", summary.auto_processing_mode);
    println!("  Interval: {}s", summary.auto_processing_interval_secs);
    if let Some(ref last_run) = summary.auto_processing_last_run {
        println!("  Last Run: {}", last_run);
    }
    if let Some(ref next_run) = summary.auto_processing_next_run {
        println!("  Next Run: {}", next_run);
    }

    // Subscription
    println!("\n[Subscription]");
    println!("  Plan: {}", summary.subscription_plan);
    println!("  Usage: {:.1}%", summary.subscription_usage * 100.0);

    // Todos
    println!("\n[Security Todos] Total: {}", summary.todo_counts.total);
    if summary.todo_counts.total > 0 {
        if summary.todo_counts.threats > 0 {
            println!("  Threats: {}", summary.todo_counts.threats);
        }
        if summary.todo_counts.policies > 0 {
            println!("  Policies: {}", summary.todo_counts.policies);
        }
        if summary.todo_counts.network_ports > 0 {
            println!("  Network Ports: {}", summary.todo_counts.network_ports);
        }
        if summary.todo_counts.network_sessions > 0 {
            println!(
                "  Network Sessions: {}",
                summary.todo_counts.network_sessions
            );
        }
        if summary.todo_counts.pwned_breaches > 0 {
            println!("  Pwned Breaches: {}", summary.todo_counts.pwned_breaches);
        }
        if summary.todo_counts.configure > 0 {
            println!("  Configuration: {}", summary.todo_counts.configure);
        }
    }

    // Actions
    println!("\n[Action History] Total: {}", summary.action_counts.total);
    if summary.action_counts.total > 0 {
        if summary.action_counts.pending > 0 {
            println!("  Pending: {}", summary.action_counts.pending);
        }
        if summary.action_counts.executed > 0 {
            println!("  Executed: {}", summary.action_counts.executed);
        }
        if summary.action_counts.escalated > 0 {
            println!("  Escalated: {}", summary.action_counts.escalated);
        }
        if summary.action_counts.failed > 0 {
            println!("  Failed: {}", summary.action_counts.failed);
        }
        if summary.action_counts.undone > 0 {
            println!("  Undone: {}", summary.action_counts.undone);
        }
    }

    // Recent Actions
    if !summary.recent_actions.is_empty() {
        println!("\n[Recent Actions] Last {}:", summary.recent_actions.len());
        for action in &summary.recent_actions {
            let status = if action.success { "OK" } else { "FAIL" };
            println!(
                "  [{}] {} - {} [{}]",
                status, action.action_type, action.result_status, action.timestamp
            );
        }
    }

    // Token Usage
    println!("\n[Token Usage]");
    println!(
        "  Last Hour: {} in / {} out",
        summary.tokens_last_hour_input, summary.tokens_last_hour_output
    );
    println!(
        "  Last 24h: {} in / {} out",
        summary.tokens_last_24h_input, summary.tokens_last_24h_output
    );

    // Slack
    println!("\n[Slack Integration]");
    println!(
        "  Configured: {}",
        if summary.slack_configured {
            "yes"
        } else {
            "no"
        }
    );
    if summary.slack_configured {
        println!("  Actions Channel: {}", summary.slack_actions_channel);
        println!(
            "  Escalations Channel: {}",
            summary.slack_escalations_channel
        );
    }

    // Status
    println!("\n[Status]");
    println!("  Success Count: {}", summary.success_count);
    println!("  Failure Count: {}", summary.failure_count);
    if !summary.last_success_time.is_empty() {
        println!("  Last Success: {}", summary.last_success_time);
    }
    if summary.error_code != "None" {
        println!(
            "  Last Error: {} - {}",
            summary.error_code, summary.error_reason
        );
    }

    println!();
    0
}

/// Process security todos with AI in background mode
pub fn background_process_agentic(mode: &str) {
    info!(
        "AI Assistant: Starting automated todo processing (mode: {})",
        mode
    );

    // Supported CLI/daemon modes: auto (execute) or analyze (recommendations only)
    let confirmation_level = match mode {
        "auto" => 0,
        "analyze" => 1,
        _ => {
            warn!(
                "AI Assistant: Unsupported mode '{}', valid options are 'auto', 'analyze', or 'disabled'",
                mode
            );
            return;
        }
    };

    let results = agentic_process_todos(confirmation_level);

    if mode == "analyze" {
        info!(
            "AI Assistant: Analyze mode completed – actions recorded for confirmation, no automatic execution performed"
        );
    }

    // Log results
    {
        let total = results.auto_resolved.len()
            + results.requires_confirmation.len()
            + results.escalated.len()
            + results.failed.len();

        if total > 0 {
            info!(
                "AI Assistant: Processed {} todos - {} auto-resolved, {} require confirmation, {} escalated, {} failed",
                total,
                results.auto_resolved.len(),
                results.requires_confirmation.len(),
                results.escalated.len(),
                results.failed.len()
            );

            if !results.requires_confirmation.is_empty() {
                for result in &results.requires_confirmation {
                    info!(
                        "  PENDING {}: todo_id={}, risk_score={:.2}, reasoning={}",
                        result.advice_type,
                        result.todo_id,
                        result.decision.risk_score,
                        result.decision.reasoning
                    );
                }
            }

            // Log escalated items with full details at WARN level for visibility
            if !results.escalated.is_empty() {
                warn!(
                    "AI Assistant: {} escalated todos need manual attention:",
                    results.escalated.len()
                );
                for result in &results.escalated {
                    warn!(
                        "  ESCALATED {}: todo_id={}, risk_score={:.2}, reasoning={}",
                        result.advice_type,
                        result.todo_id,
                        result.decision.risk_score,
                        result.decision.reasoning
                    );
                }
            }

            // Log failures
            if !results.failed.is_empty() {
                error!(
                    "AI Assistant: {} todos failed processing:",
                    results.failed.len()
                );
                for result in &results.failed {
                    error!(
                        "  → {} - {}",
                        result.advice_type,
                        result
                            .error
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string())
                    );
                }
            }
        } else {
            info!("AI Assistant: No todos to process");
        }
    }
}

pub fn background_set_agentic_loop(enabled: bool, interval_secs: u64, mode: &str) -> bool {
    use edamame_core::api::api_agentic::agentic_set_auto_processing;

    let confirmation_level = match mode {
        "auto" => 0,
        "analyze" => 1,
        "disabled" => 1,
        other => {
            warn!(
                "AI Assistant: Unsupported mode '{}' for auto-processing loop",
                other
            );
            return false;
        }
    };

    let success = agentic_set_auto_processing(enabled, interval_secs, confirmation_level);
    if success {
        if enabled {
            info!(
                "AI Assistant: Background loop enabled (interval={}s, mode={})",
                interval_secs, mode
            );
        } else {
            info!("AI Assistant: Background loop disabled");
        }
    } else {
        error!(
            "AI Assistant: Failed to {} background loop",
            if enabled { "enable" } else { "disable" }
        );
    }
    success
}
