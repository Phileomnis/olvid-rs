use async_trait::async_trait;
use color_eyre::Result;
use crossterm::event::KeyCode;
use ratatui::{layout::Flex, prelude::*, style::palette::tailwind, widgets::*};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::{Action, NavigationAction}, components::{button::render_button, tui_logo::get_tui_logo, Component, Screen}, config::Config, state::State};

#[derive(Default)]
pub struct WelcomeScreen {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    components: Vec<Box<dyn Component>>,
    selected_button: Selection,
}

impl WelcomeScreen {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, EnumIter, Display, FromRepr)]
enum Selection {
    #[default]
    Login,
    Register
}

impl Selection {
    fn previous(self) -> Self {
        let current_index: usize = self as usize;
        let previous_index = current_index.saturating_sub(1);
        Self::from_repr(previous_index).unwrap_or(self)
    }

    /// Get the next tab, if there is no next tab return the current tab.
    fn next(self) -> Self {
        let current_index = self as usize;
        let next_index = current_index.saturating_add(1);
        Self::from_repr(next_index).unwrap_or(self)
    }
}

#[async_trait]
impl Component for WelcomeScreen {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn update(&mut self, action: Action, state: &mut State) -> Result<Option<Action>> {
        match action {
            Action::Tick => {
                // add any logic here that should run on every tick
            }
            Action::Render => {
                // add any logic here that should run on every render
            },
            Action::FocusNext => {
                self.selected_button = self.selected_button.next();

            },
            Action::FocusPrev => {
                self.selected_button = self.selected_button.previous();
            },
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, state: &mut State) -> Result<()> {
        let horizontal = Layout::horizontal([Constraint::Percentage(20), Constraint::Length(75)]).flex(Flex::SpaceAround).split(area);

        let layout_logo = Layout::vertical([Constraint::Length(20)]).flex(Flex::Center).split(horizontal[0]);
        frame.render_widget(get_tui_logo(), layout_logo[0]);

        let vertical = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
        ])
        .flex(Flex::Center)
        .spacing(1)
        .split(horizontal[1]);

        let screen_title = Paragraph::new("Welcome to olvid-tui!")
            .centered()
            .wrap(Wrap { trim: true });

        frame.render_widget(screen_title, vertical[0]);
        frame.render_widget(render_button(&"I have an Olvid profile", self.selected_button == Selection::Login), vertical[1]);
        frame.render_widget(render_button(&"I don't have an Olvid profile yet", self.selected_button == Selection::Register), vertical[2]);

        Ok(())
    }

    async fn handle_key_event(&mut self, key: crossterm::event::KeyEvent, state: &mut State) -> Result<Option<Action>> {
        match key.code {
            KeyCode::Enter => Ok(Some(Action::Navigation(NavigationAction::GoToCreateProfileScreen))),
            KeyCode::Down => Ok(Some(Action::FocusNext)),
            KeyCode::Up => Ok(Some(Action::FocusPrev)),
            _ => Ok(None)
        }
    }
}

impl Screen for WelcomeScreen {
    fn init_screen(&mut self, state: &State) -> Result<()> {
        for component in self.components.iter_mut() {
            component.init()?;
        }

        Ok(())
    }
}