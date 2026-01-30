use ratatui::{
    style::Style,
    widgets::{Block, Borders, BorderType, List, ListItem},
    text::{Line, Span},
    Frame,
    layout::Rect,
};
use crate::ui::app::{AppState, Focus};
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, app: &AppState, area: Rect) {
    let focus_style = if app.focus == Focus::Operatives { 
        Style::default().fg(IsotopeTheme::BORDER_FOCUS) 
    } else { 
        Style::default().fg(IsotopeTheme::BORDER_NORMAL) 
    };

    let peers: Vec<ListItem> = app.peers.iter().map(|p| {
        ListItem::new(Line::from(vec![
            Span::raw(" > "),
            Span::styled(p, Style::default().fg(IsotopeTheme::ACCENT))
        ]))
    }).collect();

    let list = List::new(peers)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" OPERATIVES ")
            .border_type(BorderType::Thick)
            .border_style(focus_style));

    f.render_widget(list, area);
}
