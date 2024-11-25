use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use fs2::FileExt;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

/// Represents the application's state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    pub pid: Option<u32>,
    pub handle: Option<u64>,
    pub is_connected: bool,
    pub connected_domain: String,
    pub connected_user: String,
    pub last_network_activity: String,
    pub score: ScoreAPI,
    pub devices: LANScanAPI,
    pub sessions: Vec<SessionInfoAPI>,
    pub whitelist_name: String,
    pub whitelist_conformance: bool,
    pub is_outdated_backend: bool,
    pub is_outdated_threats: bool,
    pub backend_error_code: String,
    pub last_report_signature: String,
}

impl Default for State {
    fn default() -> Self {
        State {
            pid: None,
            handle: None,
            is_connected: false,
            connected_domain: "".to_string(),
            connected_user: "".to_string(),
            last_network_activity: "".to_string(),
            score: ScoreAPI::default(),
            devices: LANScanAPI::default(),
            sessions: Vec::new(),
            whitelist_name: "".to_string(),
            whitelist_conformance: true,
            is_outdated_backend: false,
            is_outdated_threats: false,
            backend_error_code: "".to_string(),
            last_report_signature: "".to_string(),
        }
    }
}

impl State {
    /// Returns the path to the state file.
    fn state_file_path() -> PathBuf {
        dirs::home_dir()
            .expect("Unable to find home directory")
            .join(".edamame_posture.yaml")
    }

    /// Loads the state from the given file.
    fn load_from_file(file: &mut File) -> Self {
        file.lock_shared().expect("Unable to lock file for reading");
        file.seek(SeekFrom::Start(0))
            .expect("Unable to seek to start");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Unable to read state file");
        let state = serde_yaml::from_str(&contents).unwrap_or_else(|e| {
            eprintln!(
                "Unable to deserialize state: {}, initializing with default",
                e
            );
            State::default()
        });
        if file.unlock().is_err() {
            eprintln!("Unable to unlock file after loading state");
        }
        state
    }

    /// Saves the state to the given file.
    fn save_to_file(&self, file: &mut File) {
        file.lock_exclusive()
            .expect("Unable to lock file for writing");
        let contents = serde_yaml::to_string(self).expect("Unable to serialize state");
        file.set_len(0).expect("Unable to truncate file");
        file.seek(SeekFrom::Start(0))
            .expect("Unable to seek to start");
        file.write_all(contents.as_bytes())
            .expect("Unable to write state file");
        file.flush().expect("Unable to flush state file");
        if file.unlock().is_err() {
            eprintln!("Unable to unlock file after saving state");
        }
    }

    /// Clears the state by resetting it to default values and writing to the state file.
    pub fn clear() {
        let path = Self::state_file_path();
        let default_state = State::default();

        // Open the file with write permissions and truncate it to overwrite existing content
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&path)
            .expect("Unable to open state file for clearing");

        // Save the default state to the file
        default_state.save_to_file(&mut file);
    }
}

/// Holds both the `State` and the associated `File`.
struct StateData {
    state: State,
    file: File,
}

impl StateData {
    /// Initializes a new `StateData` by opening the state file and loading its contents.
    fn new() -> Self {
        let path = State::state_file_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("Unable to open state file");

        // Clone the file handle to use for loading
        let mut file_clone = file.try_clone().expect("Unable to clone file handle");
        let state = State::load_from_file(&mut file_clone);

        StateData { state, file }
    }
}

lazy_static! {
    /// Global `Mutex` guarding the `StateData`.
    static ref STATE_DATA: Mutex<StateData> = Mutex::new(StateData::new());
}

/// Loads the current state from the file and updates the in-memory state.
/// Returns the loaded state.
pub fn load_state() -> State {
    let mut data = STATE_DATA.lock().unwrap();
    data.state = State::load_from_file(&mut data.file);
    data.state.clone()
}

/// Saves the provided state to the file and updates the in-memory state.
pub fn save_state(state: &State) {
    let mut data = STATE_DATA.lock().unwrap();
    let mut file = data.file.try_clone().expect("Unable to clone file handle");
    data.state = state.clone();
    data.state.save_to_file(&mut file);
}

/// Clears the state by resetting it to default both in memory and in the state file.
pub fn clear_state() {
    State::clear(); // Reset the file to default state
    STATE_DATA.lock().unwrap().state = State::default(); // Update the in-memory state to default
}

/// Struct to hold the lock guard for the state file.
pub struct StateLockGuard<'a> {
    guard: MutexGuard<'a, StateData>,
}

impl<'a> Drop for StateLockGuard<'a> {
    fn drop(&mut self) {
        // The file will be unlocked automatically when the MutexGuard is dropped
        self.guard.file.unlock().expect("Unable to unlock file");
    }
}
