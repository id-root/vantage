use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Style, Modifier, Stylize},
    widgets::{Block, Borders, Paragraph, Gauge, Wrap},
    text::{Line, Span},
    Frame,
};
use crate::ui::app::{AppState, Focus};
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Logo
            Constraint::Length(12), // Info
            Constraint::Length(4),  // Progress
            Constraint::Min(1),     // Spacer
            Constraint::Length(5),  // ID
        ])
        .split(area);

    // 1. Logo (Updated to ISOTOPE)
    let logo_text = vec![
        Line::from(""),
        Line::from(""),
        Line::from("▐░▒▓█▓▒░▌".fg(IsotopeTheme::SECONDARY)),
        Line::from(vec![
            Span::styled("▐░▒ ", Style::default().fg(IsotopeTheme::SECONDARY)),
            Span::styled("☢", Style::default().fg(IsotopeTheme::ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(" ▒░▌", Style::default().fg(IsotopeTheme::SECONDARY)),
        ]),
        Line::from("▐░▒▓█▓▒░▌".fg(IsotopeTheme::SECONDARY)),
        Line::from(""),
        Line::from("I S O T O P E".fg(IsotopeTheme::ACCENT).bold()), // Or .white() if you prefer
    ];
    
    let focus_style = if app.focus == Focus::Sidebar { 
        Style::default().fg(IsotopeTheme::BORDER_FOCUS) 
    } else { 
        Style::default().fg(IsotopeTheme::BORDER_NORMAL) 
    };
    
    let logo = Paragraph::new(logo_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(focus_style));
    f.render_widget(logo, chunks[0]);

    // 2. Info
    let stats_text = vec![
        Line::from("CHANNEL:".dim()),
        Line::from(Span::styled(format!("#{}", app.group), Style::default().fg(IsotopeTheme::WARNING).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("USER:".dim()),
        Line::from(app.username.clone().white()),
        Line::from(""),
        Line::from("ENCRYPTION:".dim()),
        Line::from(app.encryption_level.clone().fg(if app.encryption_level.contains("KYBER") { IsotopeTheme::ENCRYPTION_QUANTUM } else { IsotopeTheme::ENCRYPTION_CLASSIC })),
    ];
    
    let stats = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT).title(" INFO ").border_style(focus_style));
    f.render_widget(stats, chunks[1]);
    
    // 3. Progress
    if let Some((_, progress)) = &app.file_progress {
         let label = format!("{:.0}%", progress * 100.0);
         let gauge = Gauge::default()
             .block(Block::default().borders(Borders::ALL).title(" TRANSFER "))
             .gauge_style(Style::default().fg(IsotopeTheme::ACCENT).bg(IsotopeTheme::BACKGROUND_DARK))
             .ratio(progress.max(0.0).min(1.0))
             .label(label);
         f.render_widget(gauge, chunks[2]);
    } else {
         let block = Block::default().borders(Borders::LEFT | Borders::RIGHT).border_style(focus_style);
         f.render_widget(block, chunks[2]);
    }
    
    // 4. Spacer
    let spacer = Block::default().borders(Borders::LEFT | Borders::RIGHT).border_style(focus_style);
    f.render_widget(spacer, chunks[3]);

    // 5. Identity
    let id_block = Paragraph::new(app.identity_fp.clone())
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(IsotopeTheme::TEXT_DIM))
        .block(Block::default().borders(Borders::ALL).title(" ID ").border_style(focus_style));
    f.render_widget(id_block, chunks[4]);
}
