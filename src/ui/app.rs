use tui_input::Input;
use std::path::PathBuf;
use syntect::parsing::SyntaxSet;
use syntect::highlighting::ThemeSet;
use chrono::{DateTime, Utc, Duration};
use ratatui::widgets::ListState;

pub struct SecureMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    Sidebar,
    Chat,
    Operatives,
    Input,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Comms,
    Vault,
    Intel,
}

pub struct DashboardState {
    pub ram_usage: u64,
    pub uptime_secs: u64,
    #[allow(dead_code)]
    pub tor_status: String,
    pub upload_speed: f64,
    pub download_speed: f64,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            ram_usage: 0,
            uptime_secs: 0,
            tor_status: "CONNECTED".to_string(),
            upload_speed: 0.0,
            download_speed: 0.0,
        }
    }
}

pub struct AppState {
    // Core Data
    pub messages: Vec<SecureMessage>, 
    pub system_logs: Vec<SecureMessage>,
    pub input: Input,
    pub username: String,
    pub identity_fp: String, 
    pub status: String,
    pub encryption_level: String,
    pub peers: Vec<String>,
    pub group: String, 
    pub file_progress: Option<(String, f64)>, 
    
    // UI State
    pub focus: Focus,
    pub current_tab: Tab,
    pub dashboard_state: DashboardState,
    pub show_help: bool,
    pub list_state: ListState,
    
    // File Browser State
    pub file_browser_open: bool,
    pub current_dir: PathBuf,
    pub dir_entries: Vec<PathBuf>,
    pub browser_state: ListState,
    

    
    // Vault UI State
    pub vault_files: Vec<String>,
    pub vault_state: ListState,
    
    // Syntax Highlighting Assets
    pub syntax_set: SyntaxSet,
    pub theme_set: ThemeSet,
}

impl AppState {
    pub fn new(username: String, identity_fp: String, group: String) -> Self {
        let current_dir = std::env::current_dir()
            .or_else(|_| std::env::var("HOME").map(PathBuf::from))
            .unwrap_or_else(|_| PathBuf::from("/"));
        
        Self {
            messages: vec![],
            system_logs: vec![],
            input: Input::default(),
            username,
            identity_fp,
            status: "INITIALIZING...".to_string(),
            encryption_level: "UNSECURED".to_string(),
            peers: vec![],
            group, 
            file_progress: None,
            
            focus: Focus::Input,
            current_tab: Tab::Comms,
            dashboard_state: DashboardState::default(),
            show_help: false,
            list_state: ListState::default(),
            
            file_browser_open: false,
            current_dir,
            dir_entries: vec![],
            browser_state: ListState::default(),
            

            
            vault_files: vec![],
            vault_state: ListState::default(),
            
            syntax_set: SyntaxSet::load_defaults_newlines(),
            theme_set: ThemeSet::load_defaults(),
        }
    }

    pub fn cycle_focus(&mut self, reverse: bool) {
        use Focus::*;
        self.focus = if reverse {
            match self.focus {
                Input => Operatives,
                Operatives => Chat,
                Chat => Sidebar,
                Sidebar => Input,
            }
        } else {
            match self.focus {
                Input => Sidebar,
                Sidebar => Chat,
                Chat => Operatives,
                Operatives => Input,
            }
        };
    }

    pub fn add_msg(&mut self, sender: String, content: String) {
        self.messages.push(SecureMessage {
            sender,
            content,
            timestamp: Utc::now(),
            expires_at: None,
        });
        self.list_state.select(None); // Snap to bottom
    }

    pub fn add_ttl_msg(&mut self, sender: String, content: String, ttl_seconds: u64) {
        self.messages.push(SecureMessage {
            sender,
            content,
            timestamp: Utc::now(),
            expires_at: Some(Utc::now() + Duration::seconds(ttl_seconds as i64)),
        });
        self.list_state.select(None);
    }

    pub fn add_log(&mut self, log: String) {
        self.system_logs.push(SecureMessage {
            sender: "SYSTEM".to_string(),
            content: log,
            timestamp: Utc::now(),
            expires_at: None,
        });
        // Logic to snap to bottom of log view if we had a state for it
    }

    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.messages.retain(|msg| {
            if let Some(expiry) = msg.expires_at {
                expiry > now
            } else {
                true
            }
        });
    }

    pub fn scroll_up(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 { 0 } else { i - 1 }
            }
            None => self.messages.len().saturating_sub(1),
        };
        self.list_state.select(Some(i));
    }

    pub fn scroll_down(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.messages.len().saturating_sub(1) { None } else { Some(i + 1) }
            }
            None => None,
        };
        self.list_state.select(i);
    }
    
    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Comms => Tab::Vault,
            Tab::Vault => Tab::Intel,
            Tab::Intel => Tab::Comms,
        };
    }

    pub fn prev_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Comms => Tab::Intel,
            Tab::Vault => Tab::Comms,
            Tab::Intel => Tab::Vault,
        };
    }
    
    // --- File Browser Logic ---

    pub fn open_browser(&mut self) {
        self.file_browser_open = true;
        self.refresh_dir();
        self.browser_state.select(Some(0));
    }

    pub fn refresh_dir(&mut self) {
        self.dir_entries.clear();
        if self.current_dir.parent().is_some() {
            self.dir_entries.push(PathBuf::from(".."));
        }

        if let Ok(entries) = std::fs::read_dir(&self.current_dir) {
            let mut dirs = vec![];
            let mut files = vec![];

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path);
                }
            }
            
            dirs.sort();
            files.sort();
            
            self.dir_entries.extend(dirs);
            self.dir_entries.extend(files);
        }
    }

    pub fn browser_navigate(&mut self, up: bool) {
        if self.dir_entries.is_empty() { return; }
        
        let i = match self.browser_state.selected() {
            Some(i) => {
                if up {
                    if i == 0 { self.dir_entries.len() - 1 } else { i - 1 }
                } else {
                    if i >= self.dir_entries.len() - 1 { 0 } else { i + 1 }
                }
            }
            None => 0,
        };
        self.browser_state.select(Some(i));
    }

    pub fn browser_select(&mut self) -> Option<String> {
        if let Some(i) = self.browser_state.selected() {
            if i < self.dir_entries.len() {
                let selected = self.dir_entries[i].clone();
                if selected == PathBuf::from("..") {
                    if let Some(parent) = self.current_dir.parent() {
                        self.current_dir = parent.to_path_buf();
                        self.refresh_dir();
                        self.browser_state.select(Some(0));
                    }
                    return None;
                }
                if selected.is_dir() {
                    self.current_dir = selected;
                    self.refresh_dir();
                    self.browser_state.select(Some(0));
                    return None;
                } else {
                    self.file_browser_open = false;
                    return Some(selected.to_string_lossy().to_string());
                }
            }
        }
        None
    }
}
