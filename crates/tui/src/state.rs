use color_eyre::Result;
use engine::{entities::identity::ObvIdentity, Engine};

pub struct State {
    // pub input_mode: InputMode,
    pub current_identity: Option<ObvIdentity>,
    pub owned_identities: Vec<ObvIdentity>,
    pub olvid_engine: Engine
}

impl State {
    pub async fn init(olvid_engine: Engine) -> Result<Self> {
        let all_owned_identities = olvid_engine.get_all_owned_identities().await?;
        Ok(Self {
            olvid_engine,
            current_identity: all_owned_identities.get(0).map(|owned_identity| owned_identity.to_owned()),
            owned_identities: all_owned_identities,
        })
    }
}

#[derive(Default, PartialEq)]
pub enum InputMode {
    #[default]
    Normal,
    Insert
}