use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, List, ListItem},
    Frame,
};
use tui_input::Input;

pub struct AppState {
    pub messages: Vec<String>,
    pub input: Input,
    pub username: String,
    pub status: String,
    pub file_progress: Option<(String, f64)>, // Filename, Percentage
}

impl AppState {
    pub fn new(username: String) -> Self {
        Self {
            messages: vec![],
            input: Input::default(),
            username,
            status: "Connecting...".to_string(),
            file_progress: None,
        }
    }
}

// FIX: Signature changed from ui<B: Backend>(f: &mut Frame<B>...) to ui(f: &mut Frame...)
pub fn ui(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1), // Chat history
            Constraint::Length(3), // Input bar
            Constraint::Length(1), // Status bar
        ].as_ref())
        .split(f.size());

    // 1. Chat History
    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .map(|m| {
            let content = Line::from(Span::raw(m));
            ListItem::new(content)
        })
        .collect();
        
    let messages_widget = List::new(messages)
        .block(Block::default().borders(Borders::ALL).title(" VANTAGE Secure Channel "));
    
    f.render_widget(messages_widget, chunks[0]);

    // 2. Input Bar
    let width = chunks[1].width.max(3) - 3;
    let scroll = app.input.visual_scroll(width as usize);
    let input = Paragraph::new(app.input.value())
        .style(Style::default().fg(Color::Yellow))
        .scroll((0, scroll as u16))
        .block(Block::default().borders(Borders::ALL).title(" Message (Enter to send, /nuke for kill switch) "));
    
    f.render_widget(input, chunks[1]);
    
    // Cursor
    f.set_cursor(
        chunks[1].x + ((app.input.visual_cursor().max(scroll) - scroll) as u16) + 1,
        chunks[1].y + 1,
    );

    // 3. Status Bar
    let status_text = if let Some((file, prog)) = &app.file_progress {
        format!("📡 Sending {}: {:.1}%", file, prog * 100.0)
    } else {
        app.status.clone()
    };

    let status = Paragraph::new(status_text)
        .style(Style::default().bg(Color::Blue).fg(Color::White));
    f.render_widget(status, chunks[2]);
}
     
