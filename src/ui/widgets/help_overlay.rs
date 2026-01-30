use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Modifier},
    widgets::{Block, Borders, Clear, Row, Table},
    Frame,
};
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, area: Rect) {
    let area = centered_rect(60, 50, area);
    f.render_widget(Clear, area); // Clear background

    let block = Block::default()
        .title(" KEYBOARD SHORTCUTS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(IsotopeTheme::ACCENT))
        .style(Style::default().bg(IsotopeTheme::BACKGROUND_DARK));

    let rows = vec![
        Row::new(vec!["Global", "ESC", "Quit Application"]),
        Row::new(vec!["", "TAB", "Switch Focus"]),
        Row::new(vec!["", "?", "Toggle Help"]),
        Row::new(vec!["Input", "Enter", "Send Message"]),
        Row::new(vec!["", "Up/Down", "History Scroll"]),
        Row::new(vec!["Chat", "PgUp/PgDn", "Scroll Content"]),
        Row::new(vec!["Commands", "/send <file>", "Send File"]),
        Row::new(vec!["", "/get <id>", "Download File"]),
        Row::new(vec!["", "/vault_put", "Store in Vault"]),
        Row::new(vec!["", "/nuke", "WIPE EVERYTHING"]),
    ];

    let table = Table::new(rows, [Constraint::Length(10), Constraint::Length(10), Constraint::Min(20)])
        .block(block)
        .header(Row::new(vec!["Scope", "Key", "Action"]).style(Style::default().add_modifier(Modifier::BOLD).fg(IsotopeTheme::ACCENT)));

    f.render_widget(table, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
