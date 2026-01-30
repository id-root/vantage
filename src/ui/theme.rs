use ratatui::style::Color;

pub struct IsotopeTheme;

impl IsotopeTheme {
    pub const ACCENT: Color = Color::Cyan;
    pub const SECONDARY: Color = Color::Blue;
    pub const SUCCESS: Color = Color::Green;
    pub const ERROR: Color = Color::Red;
    pub const WARNING: Color = Color::Yellow;
    pub const TEXT_PRIMARY: Color = Color::White;
    pub const TEXT_DIM: Color = Color::DarkGray;
    pub const BACKGROUND_DARK: Color = Color::Rgb(10, 10, 10);
    pub const BORDER_FOCUS: Color = Color::Cyan;
    pub const BORDER_NORMAL: Color = Color::DarkGray;
    pub const ENCRYPTION_QUANTUM: Color = Color::Magenta;
    pub const ENCRYPTION_CLASSIC: Color = Color::Green;
    pub const THIS_USER: Color = Color::Cyan; // Added for Dashboard compatibility
}

