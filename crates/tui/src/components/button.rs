use ratatui::{style::{Color, Style, Stylize}, widgets::{Block, BorderType, Paragraph, Widget, Wrap}};
use color_eyre::{eyre::Ok, Result};

use crate::{action::Action, state::State};

use super::Component;

pub fn render_button(label: &str, selected: bool) -> impl Widget {
    let border_type = match selected {
        true => BorderType::Double,
        false => BorderType::Plain,
    };

    let button_container = Block::bordered().border_type(border_type);
    Paragraph::new(label.to_string().dark_gray())
        .centered()
        .wrap(Wrap { trim: true })
        .block(button_container)
}

pub struct Button {
    focused: bool,
    label: String,
}

impl Button {
    pub fn new(label: &str) -> Self {
        Self {
            focused: false,
            label: label.to_owned()
        }
    }

    fn border_style(&self) -> Style {
        match self.focused {
            true => Style::default().fg(Color::Blue),
            false => Style::default(),
        }
    }
}

impl Component for Button {
    fn update(&mut self, action: Action, state: &mut State) -> Result<Option<Action>> {
        match action {
            Action::Focus => {
                self.focused = true;
            }
            Action::Unfocus => {
                self.focused = false;
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
        let button_container = Block::bordered().border_style(self.border_style());
        let button = Paragraph::new(self.label.clone().dark_gray())
            .centered()
            .wrap(Wrap { trim: true })
            .block(button_container);

        frame.render_widget(button, area);
        Ok(())
    }
}
