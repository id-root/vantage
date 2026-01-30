use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};
use crate::ui::app::AppState;
use crate::ui::widgets::{sidebar, chat, operatives, status_bar, help_overlay};

pub fn draw_ui(f: &mut Frame, app: &mut AppState) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // Main Content
            Constraint::Length(1), // Status Bar
        ])
        .split(f.size());

    let content_area = main_layout[0];
    
    // Draw Tabs
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
        ])
        .split(content_area);
        
    let tab_titles = vec![" [1] COMMS ", " [2] VAULT ", " [3] INTEL "];
    let tabs = ratatui::widgets::Tabs::new(tab_titles)
        .block(ratatui::widgets::Block::default().borders(ratatui::widgets::Borders::ALL).title(" TABS "))
        .select(match app.current_tab {
            crate::ui::app::Tab::Comms => 0,
            crate::ui::app::Tab::Vault => 1,
            crate::ui::app::Tab::Intel => 2,
        })
        .style(ratatui::style::Style::default().fg(crate::ui::theme::IsotopeTheme::ACCENT))
        .highlight_style(ratatui::style::Style::default().add_modifier(ratatui::style::Modifier::BOLD).bg(crate::ui::theme::IsotopeTheme::SECONDARY));
        
    f.render_widget(tabs, chunks[0]);
    
    // Draw Tab Content
    match app.current_tab {
        crate::ui::app::Tab::Comms => {
             let content_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(20), // Sidebar
                    Constraint::Percentage(60), // Chat
                    Constraint::Percentage(20), // Operatives
                ])
                .split(chunks[1]);

            sidebar::draw(f, app, content_layout[0]);
            chat::draw(f, app, content_layout[1]);
            operatives::draw(f, app, content_layout[2]);
        },
        crate::ui::app::Tab::Vault => {
            crate::ui::widgets::vault::draw(f, app, chunks[1]);
        },
        crate::ui::app::Tab::Intel => {
            crate::ui::widgets::dashboard::draw(f, app, chunks[1]);
        }
    }
    
    status_bar::draw_status_bar(f, app, main_layout[1]);

    if app.show_help {
        help_overlay::draw(f, f.size());
    }

    // Modal for file browser (if implemented inside simple_ui or app)
    // For now file browser logic was in tui.rs, we need to port it or widgetize it.
    // For simplicity, let's keep basic browser drawing inside chat or standalone.
    // Let's migrate file browser drawing to a widget later or add it here.
    if app.file_browser_open {
       // draw_file_browser(f, app, f.size());
       // We need to implement this widget.
       crate::ui::widgets::chat::draw_file_browser(f, app, f.size());
    }
}
