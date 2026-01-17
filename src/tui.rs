use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Style, Modifier, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, BorderType, Paragraph, List, ListItem, 
        Gauge, Wrap, ListDirection, ListState, Clear
    },
    Frame,
};
use tui_input::Input;
use std::path::PathBuf;
use syntect::parsing::SyntaxSet;
use syntect::highlighting::ThemeSet;
use syntect::easy::HighlightLines;

pub struct AppState {
    pub messages: Vec<(String, String)>, 
    pub input: Input,
    pub username: String,
    pub identity_fp: String, 
    pub status: String,
    pub encryption_level: String,
    pub peers: Vec<String>,
    pub group: String, 
    pub file_progress: Option<(String, f64)>, 
    pub list_state: ListState,
    
    // File Browser State
    pub file_browser_open: bool,
    pub current_dir: PathBuf,
    pub dir_entries: Vec<PathBuf>,
    pub browser_state: ListState,
    
    // Syntax Highlighting Assets
    pub syntax_set: SyntaxSet,
    pub theme_set: ThemeSet,
}

impl AppState {
    pub fn new(username: String, identity_fp: String, group: String) -> Self {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        
        Self {
            messages: vec![],
            input: Input::default(),
            username,
            identity_fp,
            status: "INITIALIZING...".to_string(),
            encryption_level: "UNSECURED".to_string(),
            peers: vec![],
            group, 
            file_progress: None,
            list_state: ListState::default(),
            
            file_browser_open: false,
            current_dir,
            dir_entries: vec![],
            browser_state: ListState::default(),
            
            syntax_set: SyntaxSet::load_defaults_newlines(),
            theme_set: ThemeSet::load_defaults(),
        }
    }

    pub fn add_msg(&mut self, sender: String, content: String) {
        self.messages.push((sender, content));
        self.list_state.select(None); // Snap to bottom
    }

    pub fn add_log(&mut self, log: String) {
        self.messages.push(("SYSTEM".to_string(), log));
        self.list_state.select(None); // Snap to bottom
    }

    pub fn scroll_up(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    0
                } else {
                    i - 1
                }
            }
            None => self.messages.len().saturating_sub(1),
        };
        self.list_state.select(Some(i));
    }

    pub fn scroll_down(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.messages.len().saturating_sub(1) {
                    None 
                } else {
                    Some(i + 1)
                }
            }
            None => None,
        };
        self.list_state.select(i);
    }

    // --- File Browser Logic ---

    pub fn open_browser(&mut self) {
        self.file_browser_open = true;
        self.refresh_dir();
        self.browser_state.select(Some(0));
    }

    pub fn refresh_dir(&mut self) {
        self.dir_entries.clear();
        // Add ".." for parent directory if not root
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
            
            // Sort case-insensitive-ish or just default
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
                
                // Explicit check for ".." PathBuf
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
                    // File
                    self.file_browser_open = false;
                    return Some(selected.to_string_lossy().to_string());
                }
            }
        }
        None
    }
}

pub fn ui(f: &mut Frame, app: &mut AppState) {
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // Left: Sidebar
            Constraint::Percentage(60), // Center: Main Feed
            Constraint::Percentage(20), // Right: Operatives
        ])
        .split(f.size());

    draw_sidebar(f, app, main_layout[0]);
    draw_main_feed(f, app, main_layout[1]);
    draw_active_operatives(f, app, main_layout[2]);

    if app.file_browser_open {
        draw_file_browser(f, app, f.size());
    }
}

fn highlight_content(content: &str, syntax_set: &SyntaxSet, theme_set: &ThemeSet) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let theme = &theme_set.themes["base16-ocean.dark"];
    
    // Simple detection of code blocks ```lang ... ```
    // This is a naive parser. For full markdown support we'd need a markdown parser.
    // We will assume the whole message is code if it starts with ```? Or mixed?
    // Let's implement mixed: Normal text, then code block.
    
    // Actually, splitting by ``` is easier.
    let parts: Vec<&str> = content.split("```").collect();
    
    for (i, part) in parts.iter().enumerate() {
        if i % 2 == 0 {
            // Normal text (even indices: 0, 2, 4...)
            // Just split newlines and add spans
            if !part.is_empty() {
                for line in part.lines() {
                    lines.push(Line::from(line.to_string()));
                }
                // Handle trailing newline if split removed it? 
                // `lines()` removes them. We might lose empty lines. 
                // `textwrap::wrap` handles wrapping, but here we are producing Lines for ListItem.
                // Re-using textwrap here is tricky if we want highlighting.
                // For now, let's assume code blocks are usually on their own lines or we just render them.
                // If we want wrapping AND highlighting, it's complex.
                // The prompt asked for syntax highlighting.
                // For simplicity, let's not wrap code blocks, but wrap normal text?
                // Or just return Lines and let the caller wrap?
                // The caller `draw_main_feed` uses `textwrap`.
                // If we integrate highlighting, we should probably output `Vec<Line>` and maybe manually wrap normal text.
                // Let's just output lines for now and assume the view handles horizontal scroll or cut-off for code.
            }
        } else {
            // Code block (odd indices: 1, 3, 5...)
            // First line might be language
            let mut code_lines = part.lines();
            let first_line = code_lines.next().unwrap_or("");
            let lang = first_line.trim();
            
            let syntax = syntax_set.find_syntax_by_token(lang)
                .unwrap_or_else(|| syntax_set.find_syntax_plain_text());
            
            let mut h = HighlightLines::new(syntax, theme);
            
            for line in code_lines {
                let ranges: Vec<(syntect::highlighting::Style, &str)> = h.highlight_line(line, syntax_set).unwrap_or_default();
                let spans: Vec<Span> = ranges.into_iter().map(|(style, text)| {
                    let fg = style.foreground;
                    Span::styled(
                        text.to_string(),
                        Style::default().fg(Color::Rgb(fg.r, fg.g, fg.b))
                    )
                }).collect();
                lines.push(Line::from(spans));
            }
        }
    }
    
    if lines.is_empty() && !content.is_empty() {
         lines.push(Line::from(content.to_string()));
    }
    
    lines
}

fn draw_sidebar(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Logo
            Constraint::Length(8),  // Network/Group Info
            Constraint::Length(4),  // Progress Bar
            Constraint::Min(1),     // Spacer
            Constraint::Length(3),  // Fingerprint
        ])
        .split(area);

    let logo_text = vec![
        Line::from(""),
        Line::from("      ▲      ".fg(Color::Cyan)),
        Line::from("     ◢█◣     ".fg(Color::Cyan)),
        Line::from("    ◢█▀█◣    ".fg(Color::Blue)),
        Line::from("   ◢█▀ ▀█◣   ".fg(Color::Blue)),
        Line::from("  ◢█▀   ▀█◣  ".fg(Color::Blue)),
        Line::from(" V A N T A G E ".bold().white()),
        Line::from(""),
    ];
    let logo = Paragraph::new(logo_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(logo, chunks[0]);

    // [B] Info (Group + Network)
    let enc_color = if app.encryption_level.contains("KYBER") { Color::Magenta } else { Color::Green };
    let stats_text = vec![
        Line::from("CHANNEL:".dim()),
        Line::from(Span::styled(format!("#{}", app.group), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("STATUS:".dim()),
        Line::from(app.status.clone().green()),
        Line::from(""),
        Line::from("ENCRYPTION:".dim()),
        Line::from(Span::styled(app.encryption_level.clone(), Style::default().fg(enc_color))),
    ];
    let stats = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT).title(" STATUS ").border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(stats, chunks[1]);

    // [C] Embedded Progress Bar
    if let Some((_, progress)) = &app.file_progress {
        let label = format!("Tx: {:.0}%", progress * 100.0);
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" TRANSFER "))
            .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
            .ratio(progress.max(0.0).min(1.0))
            .label(label);
        f.render_widget(gauge, chunks[2]);
    } else {
        let block = Block::default().borders(Borders::LEFT | Borders::RIGHT).border_style(Style::default().fg(Color::DarkGray));
        f.render_widget(block, chunks[2]);
    }

    // [D] Spacer
    let spacer = Block::default().borders(Borders::LEFT | Borders::RIGHT).border_style(Style::default().fg(Color::DarkGray));
    f.render_widget(spacer, chunks[3]);

    // [E] Identity
    let id_block = Paragraph::new(app.identity_fp.clone())
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" ID ").border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(id_block, chunks[4]);
}

fn draw_main_feed(f: &mut Frame, app: &mut AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), 
            Constraint::Min(1),    
            Constraint::Length(3), 
            Constraint::Length(1), 
        ])
        .split(area);

    let (badge_text, badge_color) = if app.encryption_level.contains("KYBER") {
        ("🛡️ QUANTUM: KYBER-1024", Color::Magenta)
    } else {
        ("🔒 NOISE: AES-256-GCM", Color::Green)
    };
    
    let header = Paragraph::new(badge_text)
        .style(Style::default().fg(badge_color).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP | Borders::LEFT | Borders::RIGHT).border_type(BorderType::Thick));
    f.render_widget(header, chunks[0]);

    // Calculate available width for text wrapping (Total width - 2 for borders)
    let chat_width = chunks[1].width.saturating_sub(2) as usize;

    let messages: Vec<ListItem> = app.messages.iter().rev().map(|(sender, content)| {
        let (sender_style, prefix) = if sender == &app.username {
            (Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD), "You")
        } else if sender == "SYSTEM" {
            (Style::default().fg(Color::Red), "SYS")
        } else {
            (Style::default().fg(Color::Green), sender.as_str())
        };

        let header_span = Span::styled(format!("[{}] ", prefix), sender_style);
        
        let mut lines = Vec::new();
        
        // If content contains code block, use highlighting
        if content.contains("```") {
             let highlighted_lines = highlight_content(content, &app.syntax_set, &app.theme_set);
             // Add header to first line if possible, or just prepend
             // For simplicity, just add header line then content lines
             lines.push(Line::from(header_span));
             lines.extend(highlighted_lines);
        } else {
            // Text wrapping for normal messages
            let wrapped_lines = textwrap::wrap(content, chat_width);
            if wrapped_lines.is_empty() {
                 lines.push(Line::from(vec![header_span]));
            } else {
                let first_line_content = &wrapped_lines[0];
                lines.push(Line::from(vec![
                    header_span.clone(),
                    Span::raw(first_line_content.to_string())
                ]));
                for line in wrapped_lines.iter().skip(1) {
                    lines.push(Line::from(vec![
                        Span::raw(" ".repeat(prefix.len() + 3)), 
                        Span::raw(line.to_string())
                    ]));
                }
            }
        }
        
        ListItem::new(lines)
    }).collect();

    let chat = List::new(messages)
        .direction(ListDirection::BottomToTop) 
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT).border_type(BorderType::Thick))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        
    f.render_stateful_widget(chat, chunks[1], &mut app.list_state);

    let width = chunks[2].width.max(3) - 3;
    let scroll = app.input.visual_scroll(width as usize);
    let input = Paragraph::new(app.input.value())
        .style(Style::default().fg(Color::Yellow))
        .scroll((0, scroll as u16))
        .block(Block::default().borders(Borders::ALL).title(" COMMAND ").border_type(BorderType::Double));
    f.render_widget(input, chunks[2]);
    
    f.set_cursor(
        chunks[2].x + ((app.input.visual_cursor().max(scroll) - scroll) as u16) + 1,
        chunks[2].y + 1,
    );

    let current_input = app.input.value();
    let help_text = if current_input.starts_with('/') {
        if current_input.starts_with("/s") {
             "SUGGESTION: /send <path/to/file>"
        } else if current_input.starts_with("/n") {
             "SUGGESTION: /nuke (DELETE ALL DATA)"
        } else if current_input.starts_with("/q") {
             "SUGGESTION: /quit"
        } else if current_input.starts_with("/b") {
             "SUGGESTION: /browse (OPEN FILE BROWSER)"
        } else {
             "COMMANDS: /send, /get, /browse, /nuke, /quit"
        }
    } else {
        "TYPE '/' FOR COMMANDS"
    };
    
    let footer = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC));
    f.render_widget(footer, chunks[3]);
}

fn draw_file_browser(f: &mut Frame, app: &mut AppState, area: Rect) {
    // Center Popup
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(area);

    let popup_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(popup_layout[1])[1];

    f.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = app.dir_entries.iter().map(|path| {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let icon = if path.is_dir() { "📁" } else { "📄" };
        let style = if path.is_dir() { Style::default().fg(Color::Blue) } else { Style::default().fg(Color::White) };
        
        ListItem::new(Line::from(vec![
            Span::raw(format!("{} ", icon)),
            Span::styled(name, style)
        ]))
    }).collect();

    let title = format!(" BROWSE: {} ", app.current_dir.to_string_lossy());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).border_type(BorderType::Double))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, popup_area, &mut app.browser_state);
}

fn draw_active_operatives(f: &mut Frame, app: &AppState, area: Rect) {
    let peers: Vec<ListItem> = app.peers.iter().map(|p| {
        ListItem::new(Line::from(vec![
            Span::raw(" > "),
            Span::styled(p, Style::default().fg(Color::Cyan))
        ]))
    }).collect();

    let list = List::new(peers)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" OPERATIVES ")
            .border_type(BorderType::Thick)
            .style(Style::default().fg(Color::White)));
    f.render_widget(list, area);
}
