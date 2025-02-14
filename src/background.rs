use crate::base::*;
use crate::display::*;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_history::*;
use edamame_core::api::api_trust::*;
use std::thread::sleep;
use std::time::Duration;

pub fn background_get_sessions(local_traffic: bool, zeek_format: bool) -> i32 {
    let sessions = match rpc_get_lan_sessions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting LAN sessions: {}", e);
            return 1;
        }
    };

    let sessions = if !local_traffic {
        // Filter out local traffic
        filter_global_sessions(sessions.sessions)
    } else {
        sessions.sessions
    };

    // Format the connections and display them
    let sessions = if zeek_format {
        format_sessions_zeek(sessions)
    } else {
        format_sessions_log(sessions)
    };
    for session in sessions.iter() {
        println!("{}", session);
    }

    // Check whitelist conformance
    let whitelist_conformance = match rpc_get_whitelist_conformance(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(conformance) => conformance,
        Err(e) => {
            eprintln!("Error getting whitelist conformance: {}", e);
            return 1;
        }
    };
    if !whitelist_conformance {
        eprintln!("Some connections failed the whitelist check");
        return 1;
    } else {
        return 0;
    }
}

pub fn background_get_threats_info() {
    // This function does not call any rpc_ methods, so no error code return is required.
    let score = get_score(false);
    let threats = format!(
        "Threat model name: {}, date: {}, signature: {}",
        score.model_name, score.model_date, score.model_signature
    );
    println!("Threats information: {}", threats);
}

pub fn background_get_status() -> i32 {
    let connection_status = match rpc_get_connection(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => status,
        Err(e) => {
            eprintln!("Error getting connection status: {}", e);
            return 1;
        }
    };
    println!("Connection status:");
    println!(
        "  - Connected domain: {}",
        connection_status.connected_domain
    );
    println!("  - Connected user: {}", connection_status.connected_user);
    println!("  - Is connected: {}", connection_status.is_connected);
    println!(
        "  - Last network activity: {}",
        connection_status.last_network_activity
    );

    0
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
            return 1;
        }
    };
    println!("{}", signature);
    0
}

pub fn background_wait_for_connection(timeout: u64) -> i32 {
    base_get_device_info();
    base_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;

    // Fetch initial last_reported_signature
    let mut last_reported_signature = match rpc_get_last_report_signature(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("Error getting last reported signature: {}", e);
            return 1;
        }
    };

    // Fetch initial connection_status
    let mut connection_status = match rpc_get_connection(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => status,
        Err(e) => {
            eprintln!("Error getting connection status: {}", e);
            return 1;
        }
    };

    // Wait for a non-empty signature or until we time out
    while last_reported_signature.is_empty() && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;

        last_reported_signature = match rpc_get_last_report_signature(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(signature) => signature,
            Err(e) => {
                eprintln!("Error getting last reported signature: {}", e);
                return 1;
            }
        };

        connection_status = match rpc_get_connection(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error getting connection status: {}", e);
                return 1;
            }
        };

        println!(
            "Waiting for score computation and reporting to complete... (connected: {}, network activity: {})",
            connection_status.is_connected, connection_status.last_network_activity
        );
    }

    if timeout <= 0 {
        eprintln!("Timeout waiting for background process to connect to domain...");
        return 1;
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
                return 1;
            }
        };
        display_score(&score);

        // Print the lanscan results
        let devices = match rpc_get_lan_devices(
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
                return 1;
            }
        };
        display_lanscan(&devices);

        // Print the connections
        let sessions = match rpc_get_lan_sessions(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(sessions) => sessions,
            Err(e) => {
                eprintln!("Error getting LAN sessions: {}", e);
                return 1;
            }
        };
        format_sessions_log(sessions.sessions);
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
            return 1;
        }
    }
    0
}

pub fn background_get_history() {
    let history = rpc_get_history(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    );
    println!("History: {:#?}", history);
}
