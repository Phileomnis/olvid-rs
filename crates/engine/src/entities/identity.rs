use std::collections::HashMap;

use bon::Builder;
use olvid_core::cryptographic_identity::CryptographicIdentity;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

use crate::{EngineError, Result};

#[derive(Builder, Serialize, Deserialize, Debug, Clone)]
pub struct JsonIdentityDetails {
    first_name: String,
    last_name: Option<String>,
    company: Option<String>,
    position: Option<String>,
    signed_user_details: Option<String>,
    custom_fields: Option<HashMap<String, String>>,
}

impl JsonIdentityDetails {
    pub fn format_display_name(&self) -> String {
        // TODO: handle pref display
        format!("{}", self.first_name)
    }
}

impl TryInto<ObvIdentity> for OwnedIdentity {
    type Error = EngineError;

    fn try_into(self) -> std::result::Result<ObvIdentity, Self::Error> {
        let parsed_identity_details: JsonIdentityDetails = serde_json::from_str(&self.identity_details)?;
        println!("{:?}", self.bytes_owned_identity);
        Ok(ObvIdentity::new(
            CryptographicIdentity::from_raw(&self.bytes_owned_identity).map_err(|_| EngineError::Technical)?, 
            parsed_identity_details, 
            self.keycloak_managed, 
            self.active))
    }
}

#[derive(Debug, Clone)]
pub struct ObvIdentity {
    pub identity: CryptographicIdentity,
    pub identity_details: JsonIdentityDetails,
    pub keycloak_managed: bool,
    pub active: bool,
}

impl ObvIdentity {
    pub fn new(
        identity: CryptographicIdentity,
        identity_details: JsonIdentityDetails,
        keycloak_managed: bool,
        active: bool,
    ) -> Self {
        Self {
            identity,
            identity_details,
            keycloak_managed,
            active,
        }
    }
}

pub const UNPUBLISHED_DETAILS_NOTHING_NEW: u8 = 0;
pub const UNPUBLISHED_DETAILS_EXIST: u8 = 1;

pub const API_KEY_STATUS_UNKNOWN: u8 = 0;
pub const API_KEY_STATUS_VALID: u8 = 1;
pub const API_KEY_STATUS_EXPIRED: u8 = 2;
pub const API_KEY_STATUS_LICENSE_EXHAUSTED: u8 = 3;
pub const API_KEY_STATUS_OPEN_BETA_KEY: u8 = 4;
pub const API_KEY_STATUS_FREE_TRIAL_KEY: u8 = 5;
pub const API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD: u8 = 6;
pub const API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD: u8 = 7;
pub const API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED: u8 = 8;

#[derive(Clone, FromRow, Debug)]
pub struct OwnedIdentity {
    id: Option<i64>,
    bytes_owned_identity: Vec<u8>,
    display_name: String,
    identity_details: String,
    api_key_status: i64,
    unpublished_details: i64,
    photo_url: Option<String>,
    api_key_permissions: i64,
    api_key_expiration_timestamp: Option<i64>,
    keycloak_managed: bool,
    active: bool,
    custom_display_name: Option<String>,
    unlock_password: Option<Vec<u8>>,
    unlock_salt: Option<Vec<u8>>,
    pref_mute_notifications: bool,
    pref_mute_notifications_except_mentioned: bool,
    pref_mute_notifications_timestamp: Option<i64>,
    pref_show_neutral_notification_when_hidden: bool,
    capability_webrtc_continuous_ice: bool,
    capability_groups_v2: bool,
    capability_one_to_one_contacts: bool,
}

impl OwnedIdentity {
    pub fn new(obv_identity: &ObvIdentity, api_key_status: u8) -> Result<Self> {
        Ok(Self {
            id: None,
            bytes_owned_identity: obv_identity.identity.get_identity(),
            display_name: obv_identity.identity_details.format_display_name(),
            identity_details: serde_json::to_string(&obv_identity.identity_details)?,
            api_key_status: api_key_status.into(),
            unpublished_details: UNPUBLISHED_DETAILS_NOTHING_NEW.into(),
            photo_url: None,
            api_key_permissions: 0,
            api_key_expiration_timestamp: None,
            keycloak_managed: obv_identity.keycloak_managed,
            active: obv_identity.active,
            custom_display_name: None,
            unlock_password: None,
            unlock_salt: None,
            pref_mute_notifications: false,
            pref_mute_notifications_except_mentioned: true,
            pref_mute_notifications_timestamp: None,
            pref_show_neutral_notification_when_hidden: false,
            capability_webrtc_continuous_ice: false,
            capability_groups_v2: false,
            capability_one_to_one_contacts: false,
        })
    }
    
    pub async fn get_all(db :&SqlitePool) -> Result<Vec<OwnedIdentity>> {
        let owned_identites = sqlx::query_as!(OwnedIdentity,
        "SELECT * FROM identities").fetch_all(db).await?;

        Ok(owned_identites)
    }

    pub async fn insert(db: &SqlitePool, owned_identity: OwnedIdentity) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO identities 
            (
                bytes_owned_identity,
                display_name,
                identity_details,
                api_key_status,
                unpublished_details,
                photo_url,
                api_key_permissions,
                api_key_expiration_timestamp,
                keycloak_managed,
                active,
                custom_display_name,
                unlock_password,
                unlock_salt,
                pref_mute_notifications,
                pref_mute_notifications_except_mentioned,
                pref_mute_notifications_timestamp,
                pref_show_neutral_notification_when_hidden,
                capability_webrtc_continuous_ice,
                capability_groups_v2,
                capability_one_to_one_contacts
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
            "#
        )
        .bind(owned_identity.bytes_owned_identity)
        .bind(owned_identity.display_name)
        .bind(owned_identity.identity_details)
        .bind(owned_identity.api_key_status)
        .bind(owned_identity.unpublished_details)
        .bind(owned_identity.photo_url)
        .bind(owned_identity.api_key_permissions)
        .bind(owned_identity.api_key_expiration_timestamp)
        .bind(owned_identity.keycloak_managed)
        .bind(owned_identity.active)
        .bind(owned_identity.custom_display_name)
        .bind(owned_identity.unlock_password)
        .bind(owned_identity.unlock_salt)
        .bind(owned_identity.pref_mute_notifications)
        .bind(owned_identity.pref_mute_notifications_except_mentioned)
        .bind(owned_identity.pref_mute_notifications_timestamp)
        .bind(owned_identity.pref_show_neutral_notification_when_hidden)
        .bind(owned_identity.capability_webrtc_continuous_ice)
        .bind(owned_identity.capability_groups_v2)
        .bind(owned_identity.capability_one_to_one_contacts)
        .execute(db)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use olvid_core::cryptographic_identity::OwnedCryptographicIdentity;

    use crate::Engine;

    use super::{CryptographicIdentity, JsonIdentityDetails, ObvIdentity, OwnedIdentity, API_KEY_STATUS_UNKNOWN};

    #[test]
    fn test_new() {
        let owned_identity = OwnedCryptographicIdentity::generate_owned_cryptographic_identity(&"https://server.olvid.io", Engine::get_default_prng().unwrap().as_mut()).unwrap();
        let json_identity_details = JsonIdentityDetails::builder().first_name("abc".to_owned()).build();
        
        let obv_identity = ObvIdentity::new(owned_identity.get_crypto_identity(), json_identity_details, false, true);

        let owned_identity = OwnedIdentity::new(&obv_identity, API_KEY_STATUS_UNKNOWN).unwrap();
        // let raw_identity: Vec<u8> = vec![104, 116, 116, 112, 115, 58, 47, 47, 115, 101, 114, 118, 101, 114, 46, 111, 108, 118, 105, 100, 46, 105, 111, 0, 0, 128, 0, 0, 0, 31, 84, 186, 125, 239, 79, 221, 86, 70, 172, 140, 108, 137, 250, 146, 195, 155, 220, 148, 1, 163, 129, 252, 208, 251, 28, 86, 127, 134, 203, 120, 98, 50, 1, 128, 0, 0, 0, 31, 20, 204, 136, 15, 16, 37, 85, 11, 173, 33, 41, 173, 114, 59, 165, 110, 190, 73, 20, 7, 29, 143, 213, 126, 90, 233, 185, 155, 231, 239, 139, 83];
        // let test = CryptographicIdentity::from_raw(&raw_identity).unwrap();
    }
}