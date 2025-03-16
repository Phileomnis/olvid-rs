use ratatui::{style::{Color, Modifier, Style}, widgets::{Block, BorderType, Borders}};

const DEFAULT_STYLE: Style = Style {
    fg: None,
    bg: None,
    underline_color: None,
    add_modifier: Modifier::empty(),
    sub_modifier: Modifier::empty(),
};

pub struct UiStyle;

impl UiStyle {
    pub const DEFAULT: Style = DEFAULT_STYLE;
    pub const SELECTED: Style = DEFAULT_STYLE.bg(Color::Rgb(70, 70, 86));
    pub const SELECTED_BUTTON: Style = DEFAULT_STYLE.fg(Color::Rgb(118, 213, 192));
    pub const UNSELECTABLE: Style = DEFAULT_STYLE.fg(Color::DarkGray);
    pub const ERROR: Style = DEFAULT_STYLE.fg(Color::Red);
    pub const OWN_TEAM: Style = DEFAULT_STYLE.fg(Color::Green);
    pub const HEADER: Style = DEFAULT_STYLE.fg(Color::LightBlue);
    pub const NETWORK: Style = DEFAULT_STYLE.fg(Color::Rgb(204, 144, 184));
    pub const DISCONNECTED: Style = DEFAULT_STYLE.fg(Color::DarkGray);
    pub const SHADOW: Style = DEFAULT_STYLE.fg(Color::Rgb(244, 255, 232));
    pub const HIGHLIGHT: Style = DEFAULT_STYLE.fg(Color::Rgb(118, 213, 192));
    pub const OK: Style = DEFAULT_STYLE.fg(Color::Green);
    pub const WARNING: Style = DEFAULT_STYLE.fg(Color::Yellow);
    pub const STORAGE_KARTOFFEL: Style = DEFAULT_STYLE.fg(Color::Magenta);
    pub const TRAIT_KILLER: Style = DEFAULT_STYLE.fg(Color::Red);
    pub const TRAIT_SHOWPIRATE: Style = DEFAULT_STYLE.fg(Color::Magenta);
    pub const TRAIT_RELENTLESS: Style = DEFAULT_STYLE.fg(Color::Blue);
    pub const TRAIT_SPUGNA: Style = DEFAULT_STYLE.fg(Color::LightRed);
    pub const TRAIT_CRUMIRO: Style = DEFAULT_STYLE.fg(Color::Rgb(212, 175, 55));
}

pub fn default_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
}
