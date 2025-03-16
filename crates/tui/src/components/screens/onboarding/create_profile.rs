use async_trait::async_trait;
use color_eyre::{eyre::Ok, Result};
use crossterm::event::KeyCode;
use engine::entities::identity::JsonIdentityDetails;
use ratatui::{layout::Flex, prelude::*, style::palette::tailwind, widgets::*};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    action::{Action, NavigationAction},
    components::{button::{render_button, Button}, forms::text_input::TextInput, Component, Screen},
    config::Config,
    state::{InputMode, State},
    tui::Event,
};

#[derive(Default)]
pub struct CreateProfileScreen<'a> {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    inputs: Vec<TextInput<'a>>,
    components: Vec<Box<dyn Component + Send>>,
    // selected: Selection,
    focused_component_index: usize,
}

impl CreateProfileScreen<'_> {
    pub fn new() -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
            components: vec![
                Box::new(Button::new("Create a new profile"))
            ],
            focused_component_index: 0,
            inputs: vec![
                TextInput::new(Some("First name"), Some("Enter first name")),
                TextInput::new(Some("Name"), Some("Enter name (optional)")),
                TextInput::new(Some("Position"), Some("Enter position (optional)")),
                TextInput::new(Some("Company"), Some("Enter company (optional)")),

            ],
        }
    }

    fn is_button_selected(&self) -> bool {
        self.focused_component_index == self.inputs.len()
    }
}

#[async_trait]
impl Component for CreateProfileScreen<'_> {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        // Little hack to focus first element on first init
        tx.send(Action::FocusAt(0)).ok();
        self.command_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }
    
    fn update(&mut self, action: Action, state: &mut State) -> Result<Option<Action>> {
        let mut actions: Vec<Option<Action>> = vec![];
        let selection_length = self.inputs.len() + 1; // To include button
        match action {
            Action::Tick => {
                // add any logic here that should run on every tick
            }
            Action::Render => {
                // add any logic here that should run on every render
            }
            Action::Update => {}
            Action::FocusAt(index) => {
                if let Some(component) = self.inputs.get_mut(index) {
                    actions.push(component.update(Action::Focus, state)?);
                }
            }
            Action::FocusNext => {
                let next_index =
                    self.focused_component_index.saturating_add(1) % selection_length;
                if let Some(component) = self.inputs.get_mut(self.focused_component_index) {
                    actions.push(component.update(Action::Unfocus, state)?);
                }
                self.focused_component_index = next_index;
                if let Some(component) = self.inputs.get_mut(self.focused_component_index) {
                    actions.push(component.update(Action::Focus, state)?);
                }

                // Handle button selection
                if next_index == selection_length - 1 {
                    actions.push(self.components.get_mut(0).unwrap().update(Action::Focus, state)?);
                }

                if next_index == 0 {
                    actions.push(self.components.get_mut(0).unwrap().update(Action::Unfocus, state)?);
                }
            }
            Action::FocusPrev => {
                let prev_index =
                    self.focused_component_index.saturating_add(selection_length - 1) % selection_length;

                // Handle button selection
                if self.focused_component_index == selection_length - 1 {
                    actions.push(self.components.get_mut(0).unwrap().update(Action::Unfocus, state)?);
                }

                if prev_index == selection_length - 1 {
                    actions.push(self.components.get_mut(0).unwrap().update(Action::Focus, state)?);
                }

                if let Some(component) = self.inputs.get_mut(self.focused_component_index) {
                    actions.push(component.update(Action::Unfocus, state)?);
                }
                self.focused_component_index = prev_index;
                if let Some(component) = self.inputs.get_mut(self.focused_component_index) {
                    actions.push(component.update(Action::Focus, state)?);
                }
            }
            _ => {}
        }
        if let Some(tx) = &mut self.command_tx {
            actions.into_iter().flatten().for_each(|action| {
                tx.send(action).ok();
            });
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, state: &mut State) -> Result<()> {
        let horizontal = Layout::horizontal([Constraint::Length(50)])
            .flex(Flex::SpaceAround)
            .split(area);

        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .flex(Flex::Center)
        .spacing(1)
        .split(horizontal[0]);

        self.inputs[0].draw(frame, vertical[0], state)?;
        self.inputs[1].draw(frame, vertical[1], state)?;
        self.inputs[2].draw(frame, vertical[2], state)?;
        self.inputs[3].draw(frame, vertical[3], state)?;
        self.components[0].draw(frame, vertical[4], state)?;

        Ok(())
    }

    async fn handle_key_event(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut State,
    ) -> Result<Option<Action>> {
        match key.code {
            KeyCode::Enter => {
                if (self.is_button_selected()) {
                    let json_identity_details = JsonIdentityDetails::builder().first_name(self.inputs[0].get_input_content()).build();
                    state.olvid_engine.generate_simple_identity(json_identity_details).await?;
                    return Ok(Some(Action::Navigation(NavigationAction::GoToOtherScreen)));
                }
                
                Ok(None)
            },
            KeyCode::Down => Ok(Some(Action::FocusNext)),
            KeyCode::Up => Ok(Some(Action::FocusPrev)),
            _ => {
                if let Some(component) = self.inputs.get_mut(self.focused_component_index) {
                    let response = component.handle_events(Some(Event::Key(key)), state).await?;
                    return Ok(response);
                }
                Ok(None)
            },
        }
    }

    // async fn async_handle_events(&mut self, event: Option<Event>, state: &mut State) -> Result<Option<Action>> {
    //     Ok(None)
    // }
}

impl Screen for CreateProfileScreen<'_> {
    fn init_screen(&mut self, state: &State) -> Result<()> {
        for input in self.inputs.iter_mut() {
            input.init()?;
        }

        for component in self.components.iter_mut() {
            component.init()?;
        }

        Ok(())
    }
}
