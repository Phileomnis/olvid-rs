use engine::Engine;
use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Debug, Clone, PartialEq, Eq, Display, Serialize, Deserialize)]
pub enum Action {
    None,
    Tick,
    Render,
    Update,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    Help,
    FocusAt(usize),
    FocusNext,
    FocusPrev,
    Focus,
    Unfocus,
    Navigation(NavigationAction)
}

#[derive(Debug, Clone, PartialEq, Eq, Display, Serialize, Deserialize)]
pub enum NavigationAction {
    GoToOtherScreen,
    GoToHomeScreen,
    GoToCreateProfileScreen,
    GoToMessagingScreen,
    GoBack
}
