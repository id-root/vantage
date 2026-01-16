use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Style, Modifier, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, BorderType, Paragraph, List, ListItem, 
        Gauge, Wrap, ListDirection 
    },
    Frame,
};
use tui_input::Input;

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
}

impl AppState {
    pub fn new(username: String, identity_fp: String, group: String) -> Self {
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
        }
    }

    pub fn add_msg(&mut self, sender: String, content: String) {
        self.messages.push((sender, content));
    }

    pub fn add_log(&mut self, log: String) {
        self.messages.push(("SYSTEM".to_string(), log));
    }
}

pub fn ui(f: &mut Frame, app: &AppState) {
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

fn draw_main_feed(f: &mut Frame, app: &AppState, area: Rect) {
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

    // Messages with new direction
    let messages: Vec<ListItem> = app.messages.iter().rev().map(|(sender, content)| {
        let (sender_style, prefix) = if sender == &app.username {
            (Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD), "You")
        } else if sender == "SYSTEM" {
            (Style::default().fg(Color::Red), "SYS")
        } else {
            (Style::default().fg(Color::Green), sender.as_str())
        };

        let line = Line::from(vec![
            Span::styled(format!("[{}] ", prefix), sender_style),
            Span::raw(content),
        ]);
        ListItem::new(line)
    }).collect();

    let chat = List::new(messages)
        .direction(ListDirection::BottomToTop) 
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT).border_type(BorderType::Thick));
    f.render_widget(chat, chunks[1]);

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
        } else {
             "COMMANDS: /send, /get, /nuke, /quit"
        }
    } else {
        "TYPE '/' FOR COMMANDS"
    };
    
    let footer = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC));
    f.render_widget(footer, chunks[3]);
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
