use olvid_core::{crypto::prng::{PRNGHmacSHA256, PRNG}, cryptographic_identity::OwnedCryptographicIdentity};
use entities::identity::{JsonIdentityDetails, ObvIdentity, OwnedIdentity, API_KEY_STATUS_UNKNOWN};
use jose_jwk::{JwkSet, Key};
use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

pub mod entities;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("PRNG error")]
    PRNG,
    #[error("Persistence error")]
    Persistence(#[from] sqlx::Error),
    #[error("JSON encoding error")]
    JSONEncoding(#[from] serde_json::Error),
    #[error("Technical error")]
    Technical
}

pub type Result<T, E = EngineError> = std::result::Result<T, E>;

const DB_URL: &str = "sqlite://olvid_engine.db";

pub struct Engine {
    server_url: String,
    api_key: Option<Uuid>,
    prng: Box<dyn PRNG + Send>,
    db: SqlitePool
}

impl Engine {
    pub async fn init(server_url: &str, api_key: Option<Uuid>) -> Result<Self, EngineError> {
        Ok(
            Self { 
                server_url: server_url.to_owned(), 
                api_key,
                prng: Self::get_default_prng()?,
                db: Self::init_database().await?, 
            }
        )
    }

    async fn init_database() -> Result<SqlitePool> {
        if !Sqlite::database_exists(DB_URL).await.unwrap_or(false) {
            println!("Creating database {}", DB_URL);
            match Sqlite::create_database(DB_URL).await {
                Ok(_) => println!("Create db success"),
                Err(error) => panic!("error: {}", error),
            }
        } else {
            println!("Database already exists");
        }

        let db = SqlitePool::connect(DB_URL).await.unwrap();
        // let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        // let migrations = std::path::Path::new(&crate_dir).join("../migrations");

        sqlx::migrate!().run(&db).await.map_err(|err| EngineError::Persistence(sqlx::Error::Migrate(Box::new(err))))?;

        Ok(db)
    }

    pub async fn generate_simple_identity(&mut self, identity_details: JsonIdentityDetails) -> Result<ObvIdentity> {
        let owned_identity = OwnedCryptographicIdentity::generate_owned_cryptographic_identity(&self.server_url, &mut *self.prng).unwrap();
        let obv_identity = ObvIdentity::new(owned_identity.get_crypto_identity(), identity_details, false, true);

        // Store in db
        let owned_identity = OwnedIdentity::new(&obv_identity, API_KEY_STATUS_UNKNOWN)?;
        OwnedIdentity::insert(&self.db, owned_identity).await?;

        Ok(obv_identity)
    }

    pub async fn generate_identity(
        &mut self,
        identity_details: JsonIdentityDetails, 
        absolute_photo_url: &str, 
        custom_diplay_name: &str, 
        unlock_password: &[u8],
        unlock_salt: &[u8],
        keyclock_server: Option<String>,
        client_id: &str,
        client_secret: &str,
        jwks: JwkSet,
        signature_key: Key,
        serailized_keycloak_state: Option<String>,
        keycloak_transfer_restricted: bool
    ) -> Result<ObvIdentity> {
        // Todo: handle keycloak

        let owned_identity = OwnedCryptographicIdentity::generate_owned_cryptographic_identity(&self.server_url, &mut *self.prng).unwrap();
        let obv_identity = ObvIdentity::new(owned_identity.get_crypto_identity(), identity_details, false, true);

        // Store in db
        let owned_identity = OwnedIdentity::new(&obv_identity, API_KEY_STATUS_UNKNOWN)?;
        OwnedIdentity::insert(&self.db, owned_identity).await?;

        Ok(obv_identity)
    }

    pub async fn get_all_owned_identities(&self) -> Result<Vec<ObvIdentity>> {
        let owned_identities = OwnedIdentity::get_all(&self.db).await?;
        let obv_identites: Vec<ObvIdentity> = owned_identities.into_iter().map(|owned_identity| OwnedIdentity::try_into(owned_identity)).collect::<Result<Vec<ObvIdentity>>>()?;
        Ok(obv_identites)
    }

    pub fn get_default_prng() -> Result<Box<dyn PRNG + Send>> {
        let mut seed: [u8; 32] = [0; 32];
        getrandom::fill(&mut seed).map_err(|_| EngineError::PRNG)?;

        Ok(Box::new(PRNGHmacSHA256::init(&seed).map_err(|_| EngineError::PRNG)?))
    }
}