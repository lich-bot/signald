CREATE TABLE signald_kyber_prekey_store (
    account_uuid TEXT NOT NULL,
    kyber_prekey_id INTEGER NOT NULL,
    kyber_prekey_record BYTEA NOT NULL,
    is_last_resort BOOLEAN NOT NULL,
    stale_timestamp TIMESTAMP
);

CREATE TABLE signald_cdsi (
    number TEXT UNIQUE NOT NULL,
    last_seen INTEGER NOT NULL
);

ALTER TABLE signald_group_credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'pni';
ALTER TABLE signald_prekeys ADD COLUMN stale_timestamp INTEGER;

ALTER TABLE signald_servers ADD COLUMN cdsi_url VARCHAR(64);
ALTER TABLE signald_servers ADD COLUMN svr2_url VARCHAR(64);

-- these server URLs are from https://github.com/signalapp/Signal-Android/blob/main/app/build.gradle.kts
UPDATE signald_servers SET cdsi_url = 'https://cdsi.signal.org' WHERE server_uuid = '6e2eb5a8-5706-45d0-8377-127a816411a4';
UPDATE signald_servers SET svr2_url = 'https://svr2.signal.org' WHERE server_uuid = '6e2eb5a8-5706-45d0-8377-127a816411a4';

UPDATE signald_servers SET cdsi_url = 'https://cdsi.staging.signal.org' WHERE server_uuid = '97c17f0c-e53b-426f-8ffa-c052d4183f83';
UPDATE signald_servers SET svr2_url = 'https://svr2.staging.signal.org' WHERE server_uuid = '97c17f0c-e53b-426f-8ffa-c052d4183f83';
