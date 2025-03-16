use async_trait::async_trait;
use color_eyre::Result;
use crossterm::event::KeyCode;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::{Action, NavigationAction}, components::{Component, Screen}, config::Config, state::State};

#[derive(Default)]
pub struct OtherScreen {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    components: Vec<Box<dyn Component>>
}

impl OtherScreen {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Component for OtherScreen {
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
            }
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, state: &mut State) -> Result<()> {
        frame.render_widget(Paragraph::new("Other Screen"), area);
        Ok(())
    }

    async fn handle_key_event(&mut self, key: crossterm::event::KeyEvent, state: &mut State) -> Result<Option<Action>> {
        match key.code {
            KeyCode::Enter => Ok(Some(Action::Navigation(NavigationAction::GoBack))),
            _ => Ok(None)
        }
    }
}

impl Screen for OtherScreen {
    fn init_screen(&mut self, state: &State) -> Result<()> {
        for component in self.components.iter_mut() {
            component.init()?;
        }
        Ok(())
    }
}