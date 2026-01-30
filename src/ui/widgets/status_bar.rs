use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Modifier},
    widgets::{Paragraph},
    Frame,
};
use crate::ui::app::AppState;
use crate::ui::theme::IsotopeTheme;
use chrono::Local;

pub fn draw_status_bar(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(15), // Status/Online
            Constraint::Length(20), // Encryption
            Constraint::Min(10),    // Message Stats / Spacer
            Constraint::Length(25), // Shortcuts hint
            Constraint::Length(10), // Clock
        ])
        .split(area);

    // 1. Connection Status
    let (status_text, status_color) = if app.status == "ONLINE" {
        (" 🟢 ONLINE ", IsotopeTheme::SUCCESS)
    } else {
        (" 🔴 PREPARING ", IsotopeTheme::WARNING)
    };
    f.render_widget(
        Paragraph::new(status_text)
            .style(Style::default().bg(IsotopeTheme::BACKGROUND_DARK).fg(status_color).add_modifier(Modifier::BOLD)),
        chunks[0]
    );

    // 2. Encryption
    let enc_color = if app.encryption_level.contains("KYBER") {
        IsotopeTheme::ENCRYPTION_QUANTUM
    } else {
        IsotopeTheme::ENCRYPTION_CLASSIC
    };
    f.render_widget(
        Paragraph::new(format!(" 🛡️ {} ", app.encryption_level))
            .style(Style::default().bg(IsotopeTheme::BACKGROUND_DARK).fg(enc_color)),
        chunks[1]
    );

    // 3. Stats
    let msg_count = app.messages.len();
    f.render_widget(
        Paragraph::new(format!(" {} msgs ", msg_count))
            .style(Style::default().fg(IsotopeTheme::TEXT_DIM).bg(IsotopeTheme::BACKGROUND_DARK)),
        chunks[2]
    );

    // 4. Hints
    f.render_widget(
        Paragraph::new(" ESC Quit | ? Help ")
            .style(Style::default().fg(IsotopeTheme::ACCENT).bg(IsotopeTheme::BACKGROUND_DARK)),
        chunks[3]
    );

    // 5. Clock
    let time = Local::now().format("%H:%M:%S").to_string();
    f.render_widget(
        Paragraph::new(time)
            .style(Style::default().fg(IsotopeTheme::TEXT_PRIMARY).bg(IsotopeTheme::BACKGROUND_DARK).add_modifier(Modifier::BOLD)),
        chunks[4]
    );
}
