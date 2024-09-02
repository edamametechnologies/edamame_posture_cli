use edamame_core::api::api_lanscan::LANScanAPI;
use edamame_core::api::api_score::ScoreAPI;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub pid: Option<u32>,
    pub handle: Option<u64>,
    pub is_success: bool,
    pub connected_domain: String,
    pub connected_user: String,
    pub last_network_activity: String,
    pub score: ScoreAPI,
    pub devices: LANScanAPI,
}

impl Default for State {
    fn default() -> Self {
        State {
            pid: None,
            handle: None,
            is_success: false,
            connected_domain: "".to_string(),
            connected_user: "".to_string(),
            last_network_activity: "".to_string(),
            score: ScoreAPI::default(),
            devices: LANScanAPI::default(),
        }
    }
}

impl State {
    pub fn load() -> Self {
        let path = Self::state_file_path();
        if path.exists() {
            let mut file = File::open(&path).expect("Unable to open state file");
            file.lock_shared().expect("Unable to lock file for reading");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("Unable to read state file");
            let state: State = match serde_yaml::from_str(&contents) {
                Ok(state) => state,
                Err(e) => {
                    eprintln!("Unable to deserialize state: {}, cleaning it", e);
                    Self::clear();
                    State::default()
                }
            };
            file.unlock().expect("Unable to unlock file");
            state
        } else {
            State {
                pid: None,
                handle: None, // Initialize handle
                is_success: false,
                connected_domain: "".to_string(),
                connected_user: "".to_string(),
                last_network_activity: "".to_string(),
                score: ScoreAPI::default(),
                devices: LANScanAPI::default(),
            }
        }
    }

    pub fn save(&self) {
        let path = Self::state_file_path();
        let mut file = File::create(&path).expect("Unable to create state file");
        file.lock_exclusive()
            .expect("Unable to lock file for writing, is another instance running?");
        let contents = serde_yaml::to_string(self).expect("Unable to serialize state");
        file.write_all(contents.as_bytes())
            .expect("Unable to write state file");
        file.unlock().expect("Unable to unlock file");
    }

    fn state_file_path() -> PathBuf {
        dirs::home_dir()
            .expect("Unable to find home directory")
            .join(".edamame_posture.yaml")
    }

    pub fn clear() {
        let path = Self::state_file_path();
        if path.exists() {
            fs::remove_file(path).expect("Unable to delete state file");
        }
    }
}
