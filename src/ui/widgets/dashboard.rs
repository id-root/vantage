use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Sparkline},
    text::{Line, Span},
    Frame,
};
use crate::ui::app::AppState;
use crate::ui::theme::IsotopeTheme;

pub fn draw(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header Stats
            Constraint::Length(10), // Network Graphs
            Constraint::Min(0),     // Logs / Status
        ])
        .split(area);

    draw_header_stats(f, app, chunks[0]);
    draw_network_graphs(f, app, chunks[1]); // Used here
    draw_system_logs(f, app, chunks[2]);    // Used here
}

fn draw_header_stats(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);
        
    let style = Style::default().fg(IsotopeTheme::ACCENT);
    
    // Cipher
    let cipher = Paragraph::new(app.encryption_level.as_str())
        .block(Block::default().borders(Borders::ALL).title(" CIPHER "))
        .style(if app.encryption_level == "POST-QUANTUM" { Style::default().fg(IsotopeTheme::SUCCESS) } else { style });
    f.render_widget(cipher, chunks[0]);
    
    // Identity
    let identity = Paragraph::new(format!("{} @ {}", app.username, &app.identity_fp[..8]))
        .block(Block::default().borders(Borders::ALL).title(" IDENTITY "))
        .style(Style::default().fg(IsotopeTheme::THIS_USER));
    f.render_widget(identity, chunks[1]);
    
    // Uptime
    let uptime = Paragraph::new(format!("{}s", app.dashboard_state.uptime_secs))
        .block(Block::default().borders(Borders::ALL).title(" UPTIME "))
        .style(style);
    f.render_widget(uptime, chunks[2]);
    
    // RAM
    let ram = Paragraph::new(format!("{} MB", app.dashboard_state.ram_usage))
        .block(Block::default().borders(Borders::ALL).title(" RAM "))
        .style(style);
    f.render_widget(ram, chunks[3]);
}

fn draw_network_graphs(f: &mut Frame, _app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(area);
        
    // Placeholder Sparklines (Mock Data)
    // Real implementation would track history in DashboardState
    let data_up = [2, 4, 10, 5, 2, 8, 12, 5, 30, 50, 20, 10, 5, 2, 1, 0];
    let data_down = [10, 20, 50, 30, 60, 80, 40, 30, 20, 10, 5, 2, 1, 5, 10, 20];
    
    let sparkline_up = Sparkline::default()
        .block(Block::default().title(" UPLOAD TRAFFIC ").borders(Borders::ALL))
        .data(&data_up)
        .style(Style::default().fg(IsotopeTheme::WARNING));
    f.render_widget(sparkline_up, chunks[0]);
    
    let sparkline_down = Sparkline::default()
        .block(Block::default().title(" DOWNLOAD TRAFFIC ").borders(Borders::ALL))
        .data(&data_down)
        .style(Style::default().fg(IsotopeTheme::SUCCESS));
    f.render_widget(sparkline_down, chunks[1]);
}

fn draw_system_logs(f: &mut Frame, app: &AppState, area: Rect) {
    let logs: Vec<Line> = app.system_logs.iter()
        .rev()
        .take(10)
        .map(|m| {
             Line::from(vec![
                 Span::styled(format!("[{}] ", m.timestamp.format("%H:%M:%S")), Style::default().fg(Color::DarkGray)),
                 Span::styled(&m.content, Style::default().fg(IsotopeTheme::TEXT_PRIMARY)),
             ])
        })
        .collect();
        
    let para = Paragraph::new(logs)
        .block(Block::default().borders(Borders::ALL).title(" SYSTEM EVENT LOG "))
        .wrap(ratatui::widgets::Wrap { trim: true });
        
    f.render_widget(para, area);
}
