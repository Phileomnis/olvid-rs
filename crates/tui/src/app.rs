use color_eyre::Result;
use crossterm::event::KeyEvent;
use engine::Engine;
use ratatui::prelude::Rect;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::{
    action::{Action, NavigationAction},
    components::{
        other::OtherScreen, screens::{
            messaging::messaging_screen::MessagingScreen,
            onboarding::{create_profile::CreateProfileScreen, welcome::WelcomeScreen},
        }, Component, Screen
    },
    config::Config,
    state::State,
    tui::{Event, Tui},
};

pub struct App {
    config: Config,
    tick_rate: f64,
    frame_rate: f64,
    // components: Vec<Box<dyn Component>>,
    navigation_stack: Vec<Box<dyn Screen>>,
    should_quit: bool,
    should_suspend: bool,
    mode: Mode,
    last_tick_key_events: Vec<KeyEvent>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    state: State,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Home,
}

impl App {
    pub async fn new(tick_rate: f64, frame_rate: f64) -> Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        let olvid_engine = Engine::init(&"https://server.olvid.io", None)
            .await
            .expect("Failed to init olvid engine");

        let state = State::init(olvid_engine).await?;

        Ok(Self {
            tick_rate,
            frame_rate,
            navigation_stack: vec![],
            should_quit: false,
            should_suspend: false,
            config: Config::new()?,
            mode: Mode::Home,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            state,
        })
    }

    async fn get_initial_screen(&self) -> Result<Box<dyn Screen>> {
        let owned_identities = &self.state.owned_identities;

        if owned_identities.len() > 0 {
            return Ok(Box::new(MessagingScreen::new()));
        }

        Ok(Box::new(WelcomeScreen::new()))
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut tui = Tui::new()?
            // .mouse(true) // uncomment this line to enable mouse support
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate);
        tui.enter()?;

        // for component in self.components.iter_mut() {
        //     component.register_action_handler(self.action_tx.clone())?;
        // }
        // for component in self.components.iter_mut() {
        //     component.register_config_handler(self.config.clone())?;
        // }
        // for component in self.components.iter_mut() {
        //     component.init(tui.size()?)?;
        // }
        self.navigation_stack.push(self.get_initial_screen().await?);

        for screen in self.navigation_stack.iter_mut() {
            screen.register_action_handler(self.action_tx.clone())?;
        }
        for screen in self.navigation_stack.iter_mut() {
            screen.register_config_handler(self.config.clone())?;
        }
        for screen in self.navigation_stack.iter_mut() {
            screen.init_screen(&self.state)?;
            screen.focus()?;
        }

        let action_tx = self.action_tx.clone();
        loop {
            self.handle_events(&mut tui).await?;
            self.handle_actions(&mut tui)?;
            if self.should_suspend {
                tui.suspend()?;
                action_tx.send(Action::Resume)?;
                action_tx.send(Action::ClearScreen)?;
                // tui.mouse(true);
                tui.enter()?;
            } else if self.should_quit {
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        Ok(())
    }

    async fn handle_events(&mut self, tui: &mut Tui) -> Result<()> {
        let Some(event) = tui.next_event().await else {
            return Ok(());
        };
        let action_tx = self.action_tx.clone();
        match event {
            Event::Quit => action_tx.send(Action::Quit)?,
            Event::Tick => action_tx.send(Action::Tick)?,
            Event::Render => action_tx.send(Action::Render)?,
            Event::Resize(x, y) => action_tx.send(Action::Resize(x, y))?,
            Event::Key(key) => self.handle_key_event(key)?,
            _ => {}
        }

        if let Some(screen) = self.navigation_stack.last_mut() {
            if let Some(action) = screen.handle_events(Some(event.clone()), &mut self.state).await? {
                action_tx.send(action)?
            }
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        let action_tx = self.action_tx.clone();
        let Some(keymap) = self.config.keybindings.get(&self.mode) else {
            return Ok(());
        };
        match keymap.get(&vec![key]) {
            Some(action) => {
                info!("Got action: {action:?}");
                action_tx.send(action.clone())?;
            }
            _ => {
                // If the key was not handled as a single key action,
                // then consider it for multi-key combinations.
                self.last_tick_key_events.push(key);

                // Check for multi-key combinations
                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                    info!("Got action: {action:?}");
                    action_tx.send(action.clone())?;
                }
            }
        }
        Ok(())
    }

    fn handle_actions(&mut self, tui: &mut Tui) -> Result<()> {
        while let Ok(action) = self.action_rx.try_recv() {
            if action != Action::Tick && action != Action::Render {
                debug!("{action:?}");
            }
            match action {
                Action::Tick => {
                    self.last_tick_key_events.drain(..);
                }
                Action::Quit => self.should_quit = true,
                Action::Suspend => self.should_suspend = true,
                Action::Resume => self.should_suspend = false,
                Action::ClearScreen => tui.terminal.clear()?,
                Action::Resize(w, h) => self.handle_resize(tui, w, h)?,
                Action::Render => self.render(tui)?,
                Action::Navigation(ref nav_action) => self.handle_navigation(nav_action.clone())?,
                _ => {}
            }

            // for component in self.components.iter_mut() {
            //     if let Some(action) = component.update(action.clone())? {
            //         self.action_tx.send(action)?
            //     };
            // }
            if let Some(screen) = self.navigation_stack.last_mut() {
                if let Some(action) = screen.update(action.clone(), &mut self.state)? {
                    self.action_tx.send(action)?
                };
            }
            // for screen in self.screens.iter_mut() {
            //     if let Some(action) = screen.update(action.clone())? {
            //         self.action_tx.send(action)?
            //     };
            // }
        }
        Ok(())
    }

    fn handle_navigation(&mut self, nav_action: NavigationAction) -> Result<()> {
        match nav_action {
            NavigationAction::GoToOtherScreen => self.navigate_to(Box::new(OtherScreen::new())),
            NavigationAction::GoToHomeScreen => todo!("def"),
            NavigationAction::GoBack => {
                self.get_current_screen().unwrap().unfocus()?;
                self.navigation_stack.pop();
                self.get_current_screen().unwrap().focus()?;
                Ok(())
            }
            NavigationAction::GoToCreateProfileScreen => {
                self.navigate_to(Box::new(CreateProfileScreen::new()))
            }
            NavigationAction::GoToMessagingScreen => {
                self.navigate_to(Box::new(MessagingScreen::new()))
            }
        }
    }

    fn navigate_to(&mut self, mut screen: Box<dyn Screen>) -> Result<()> {
        self.get_current_screen().unwrap().unfocus()?;
        screen.register_action_handler(self.action_tx.clone())?;
        self.navigation_stack.push(screen);
        self.get_current_screen().unwrap().focus()?;
        Ok(())
    }

    fn get_current_screen(&mut self) -> Option<&mut Box<dyn Screen>> {
        self.navigation_stack.last_mut()
    }

    fn handle_resize(&mut self, tui: &mut Tui, w: u16, h: u16) -> Result<()> {
        tui.resize(Rect::new(0, 0, w, h))?;
        self.render(tui)?;
        Ok(())
    }

    fn render(&mut self, tui: &mut Tui) -> Result<()> {
        tui.draw(|frame| {
            // for component in self.components.iter_mut() {
            //     if let Err(err) = component.draw(frame, frame.area()) {
            //         let _ = self
            //             .action_tx
            //             .send(Action::Error(format!("Failed to draw: {:?}", err)));
            //     }
            // }
            // for screen in self.screens.iter_mut() {
            //     if let Err(err) = screen.draw(frame, frame.area()) {
            //         let _ = self
            //             .action_tx
            //             .send(Action::Error(format!("Failed to draw: {:?}", err)));
            //     }
            // }
            if let Some(screen) = self.navigation_stack.last_mut() {
                if let Err(err) = screen.draw(frame, frame.area(), &mut self.state) {
                    let _ = self
                        .action_tx
                        .send(Action::Error(format!("Failed to draw: {:?}", err)));
                }
            }
        })?;
        Ok(())
    }
}
