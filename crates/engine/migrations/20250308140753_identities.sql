CREATE TABLE IF NOT EXISTS identities 
(
    id INTEGER PRIMARY KEY NOT NULL,
    bytes_owned_identity BLOB NOT NULL,
    display_name TEXT NOT NULL,
    identity_details TEXT NOT NULL,
    api_key_status INTEGER NOT NULL,
    unpublished_details INTEGER NOT NULL,
    photo_url TEXT,
    api_key_permissions INTEGER NOT NULL,
    api_key_expiration_timestamp INTEGER,
    keycloak_managed BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL,
    custom_display_name TEXT,
    unlock_password BLOB,
    unlock_salt BLOB,
    pref_mute_notifications BOOLEAN NOT NULL,
    pref_mute_notifications_except_mentioned BOOLEAN NOT NULL,
    pref_mute_notifications_timestamp INTEGER,
    pref_show_neutral_notification_when_hidden BOOLEAN NOT NULL,
    capability_webrtc_continuous_ice BOOLEAN NOT NULL,
    capability_groups_v2 BOOLEAN NOT NULL,
    capability_one_to_one_contacts BOOLEAN NOT NULL
);