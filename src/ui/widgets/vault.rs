use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListDirection},
    text::{Line, Span},
    Frame,
};
use crate::ui::app::AppState;
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, app: &mut AppState, area: Rect) {
    let items: Vec<ListItem> = app.vault_files.iter().map(|name| {
        ListItem::new(Line::from(vec![
            Span::styled("🔒 ", Style::default().fg(IsotopeTheme::ACCENT)),
            Span::styled(name, Style::default().fg(IsotopeTheme::TEXT_PRIMARY)),
        ]))
    }).collect();

    let title = format!(" SECURE VAULT ACCESS ({}) ", app.vault_files.len());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(IsotopeTheme::ACCENT)))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED).fg(IsotopeTheme::SECONDARY))
        .direction(ListDirection::TopToBottom);

    f.render_stateful_widget(list, area, &mut app.vault_state);
}
