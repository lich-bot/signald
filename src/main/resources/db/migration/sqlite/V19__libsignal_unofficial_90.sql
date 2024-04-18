CREATE TABLE kyber_prekey_store (
    account_uuid TEXT NOT NULL,
    kyber_prekey_id INTEGER NOT NULL,
    kyber_prekey_record BLOB NOT NULL,
    is_last_resort BOOLEAN NOT NULL,
    stale_timestamp DATETIME
);

ALTER TABLE group_credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT "pni";
ALTER TABLE prekeys ADD COLUMN stale_timestamp INTEGER;