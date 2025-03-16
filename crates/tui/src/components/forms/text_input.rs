use std::default;

use crate::{
    action::Action,
    components::Component,
    state::{InputMode, State},
};
use async_trait::async_trait;
use color_eyre::{eyre::Ok, Result};
use crossterm::event::KeyCode;
use ratatui::{
    style::{Color, Modifier, Style},
    widgets::{Block, Borders},
};
use tui_textarea::TextArea;

pub struct TextInput<'a> {
    focused: bool,
    label: Option<String>,
    placeholder: Option<String>,
    text_area: TextArea<'a>,
}

impl<'a> TextInput<'a> {
    pub fn new(label: Option<&'a str>, placeholder: Option<&'a str>) -> Self {
        let mut text_area = TextArea::default();
        text_area.set_cursor_line_style(Style::default());

        Self {
            focused: false,
            text_area,
            label: label.map(str::to_string),
            placeholder: placeholder.map(str::to_string),
        }
    }

    fn border_style(&self) -> Style {
        match self.focused {
            true => Style::default().fg(Color::Blue),
            false => Style::default(),
        }
    }

    pub fn get_input_content(&self) -> String {
        self.text_area.lines().join("\n")
    }

    // fn block(&self) -> Block {
    //     match self.focused {
    //         true => ,
    //         false => todo!(),
    //     }
    // }
}

#[async_trait]
impl Component for TextInput<'_> {
    fn update(&mut self, action: Action, state: &mut State) -> Result<Option<Action>> {
        match action {
            Action::Focus => {
                self.focused = true;
                // state.input_mode = InputMode::Insert;
            }
            Action::Unfocus => {
                self.focused = false;
                // state.input_mode = InputMode::Normal;
            }
            _ => {}
        };
        Ok(None)
    }

    fn draw(
        &mut self,
        frame: &mut ratatui::Frame,
        area: ratatui::prelude::Rect,
        state: &mut State,
    ) -> Result<()> {
        if let Some(placeholder_text) = &self.placeholder {
            self.text_area.set_placeholder_text(placeholder_text);
        }

        let mut block = Block::default().borders(Borders::ALL);
        if let Some(label_text) = &self.label {
            block = block.title(label_text.clone());
        }

        self.text_area
            .set_block(block.border_style(self.border_style()));

        frame.render_widget(&self.text_area, area);
        Ok(())
    }

    async fn handle_key_event(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut State,
    ) -> Result<Option<Action>> {
        if self.focused {
            self.text_area.input(key);
        }

        Ok(Some(Action::Update))
    }
}
