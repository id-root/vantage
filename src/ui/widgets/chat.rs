use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    widgets::{Block, Borders, Paragraph, List, ListItem, ListDirection, Clear},
    text::{Line, Span},
    Frame,
};
use crate::ui::app::{AppState, Focus};
use crate::ui::theme::IsotopeTheme;
use syntect::easy::HighlightLines;
use syntect::parsing::SyntaxSet;
use syntect::highlighting::{ThemeSet, Style as SynStyle};

pub fn draw(f: &mut Frame, app: &mut AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // Messages
            Constraint::Length(3), // Input
        ])
        .split(area);

    let focus_style = if app.focus == Focus::Chat { 
        Style::default().fg(IsotopeTheme::BORDER_FOCUS) 
    } else { 
        Style::default().fg(IsotopeTheme::BORDER_NORMAL) 
    };

    // Chat Area
    let chat_width = chunks[0].width.saturating_sub(2) as usize;
    let messages: Vec<ListItem> = app.messages.iter().rev().map(|msg| {
        let sender = &msg.sender;
        let content = &msg.content;
        let time_str = msg.timestamp.format("%H:%M").to_string();

        let (sender_style, prefix) = if sender == &app.username {
            (Style::default().fg(IsotopeTheme::ACCENT).add_modifier(Modifier::BOLD), "You")
        } else if sender == "SYSTEM" {
            (Style::default().fg(IsotopeTheme::ERROR), "SYS")
        } else {
            (Style::default().fg(IsotopeTheme::SUCCESS), sender.as_str())
        };

        let header_span = Span::styled(format!("[{}] {}: ", time_str, prefix), sender_style);
        
        // Highlight logic
        let mut lines = Vec::new();
        if content.contains("```") {
             lines.push(Line::from(header_span));
             lines.extend(highlight_content(content, &app.syntax_set, &app.theme_set));
        } else {
            let wrapped = textwrap::wrap(content, chat_width);
            if wrapped.is_empty() {
                lines.push(Line::from(header_span));
            } else {
                lines.push(Line::from(vec![
                    header_span,
                    Span::raw(wrapped[0].to_string())
                ]));
                for line in wrapped.iter().skip(1) {
                     lines.push(Line::from(vec![
                         Span::raw(" ".repeat(time_str.len() + prefix.len() + 4)),
                         Span::raw(line.to_string())
                     ]));
                }
            }
        }
        ListItem::new(lines)
    }).collect();

    let list = List::new(messages)
        .direction(ListDirection::BottomToTop)
        .block(Block::default().borders(Borders::ALL).border_style(focus_style))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        
    f.render_stateful_widget(list, chunks[0], &mut app.list_state);

    // Input Area
    let input_focus_style = if app.focus == Focus::Input { 
        Style::default().fg(IsotopeTheme::BORDER_FOCUS) 
    } else { 
        Style::default().fg(IsotopeTheme::BORDER_NORMAL) 
    };
    
    let width = chunks[1].width.max(3) - 3;
    let scroll = app.input.visual_scroll(width as usize);
    let input = Paragraph::new(app.input.value())
        .style(Style::default().fg(IsotopeTheme::WARNING))
        .scroll((0, scroll as u16))
        .block(Block::default().borders(Borders::ALL).title(" INPUT ").border_style(input_focus_style));
    f.render_widget(input, chunks[1]);
    
    if app.focus == Focus::Input {
        f.set_cursor(
            chunks[1].x + ((app.input.visual_cursor().max(scroll) - scroll) as u16) + 1,
            chunks[1].y + 1,
        );
    }
}

pub fn draw_file_browser(f: &mut Frame, app: &mut AppState, area: Rect) {
    let popup_area = centered_rect(60, 60, area);
    f.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = app.dir_entries.iter().map(|path| {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let icon = if path.is_dir() { "📁" } else { "📄" };
        let style = if path.is_dir() { Style::default().fg(IsotopeTheme::SECONDARY) } else { Style::default().fg(IsotopeTheme::TEXT_PRIMARY) };
        
        ListItem::new(Line::from(vec![
            Span::raw(format!("{} ", icon)),
            Span::styled(name, style)
        ]))
    }).collect();

    let title = format!(" BROWSE: {} ", app.current_dir.to_string_lossy());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(IsotopeTheme::ACCENT)))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, popup_area, &mut app.browser_state);
}

fn highlight_content(content: &str, syntax_set: &SyntaxSet, theme_set: &ThemeSet) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let theme = &theme_set.themes["base16-ocean.dark"];
    let parts: Vec<&str> = content.split("```").collect();
    
    for (i, part) in parts.iter().enumerate() {
        if i % 2 == 0 {
             for line in part.lines() {
                 lines.push(Line::from(line.to_string()));
             }
        } else {
             let mut code_lines = part.lines();
             let first_line = code_lines.next().unwrap_or("");
             let lang = first_line.trim();
             let syntax = syntax_set.find_syntax_by_token(lang)
                 .unwrap_or_else(|| syntax_set.find_syntax_plain_text());
             let mut h = HighlightLines::new(syntax, theme);
             for line in code_lines {
                 let ranges: Vec<(SynStyle, &str)> = h.highlight_line(line, syntax_set).unwrap_or_default();
                 let spans: Vec<Span> = ranges.into_iter().map(|(style, text)| {
                     let fg = style.foreground;
                     Span::styled(text.to_string(), Style::default().fg(Color::Rgb(fg.r, fg.g, fg.b)))
                 }).collect();
                 lines.push(Line::from(spans));
             }
        }
    }
    lines
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
