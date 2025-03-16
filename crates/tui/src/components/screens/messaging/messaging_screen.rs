use async_trait::async_trait;
use color_eyre::Result;
use crossterm::event::KeyCode;
use ratatui::{layout::Flex, prelude::*, style::palette::tailwind, widgets::*};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::{Action, NavigationAction}, components::{button::render_button, Component, Screen}, config::Config, state::State};

#[derive(Default)]
pub struct MessagingScreen {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    components: Vec<Box<dyn Component>>,
}

impl MessagingScreen {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Component for MessagingScreen {
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
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, state: &mut State) -> Result<()> {
        let horizontal = Layout::horizontal([Constraint::Length(50)]).flex(Flex::SpaceAround).split(area);
        let test = state.current_identity.as_ref().unwrap();
        
        frame.render_widget(Paragraph::new(test.identity_details.format_display_name()), horizontal[0]);

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

impl Screen for MessagingScreen {
    fn init_screen(&mut self, state: &State) -> Result<()> {
        for component in self.components.iter_mut() {
            component.init()?;
        }

        Ok(())
    }
}