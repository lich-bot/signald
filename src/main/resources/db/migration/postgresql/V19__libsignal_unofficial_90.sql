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
ALTER TABLE signald_servers ADD COLUMN svr2_mrenclave VARCHAR(64);

-- these URLs and values are from https://github.com/signalapp/Signal-Android/blob/main/app/build.gradle.kts
UPDATE signald_servers SET cdsi_url = 'https://cdsi.signal.org' WHERE server_uuid = '6e2eb5a8-5706-45d0-8377-127a816411a4';
UPDATE signald_servers SET svr2_url = 'https://svr2.signal.org' WHERE server_uuid = '6e2eb5a8-5706-45d0-8377-127a816411a4';
UPDATE signald_servers SET cds_mrenclave = "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57" WHERE server_uuid = "6e2eb5a8-5706-45d0-8377-127a816411a4";
UPDATE signald_servers SET cds_mrenclave = "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57" WHERE server_uuid = "97c17f0c-e53b-426f-8ffa-c052d4183f83";
UPDATE signald_servers SET svr2_mrenclave = "a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97" WHERE server_uuid = "6e2eb5a8-5706-45d0-8377-127a816411a4";
UPDATE signald_servers SET svr2_mrenclave = "a6622ad4656e1abcd0bc0ff17c229477747d2ded0495c4ebee7ed35c1789fa97" WHERE server_uuid = "97c17f0c-e53b-426f-8ffa-c052d4183f83";
UPDATE signald_servers SET cdsi_url = 'https://cdsi.staging.signal.org' WHERE server_uuid = '97c17f0c-e53b-426f-8ffa-c052d4183f83';
UPDATE signald_servers SET svr2_url = 'https://svr2.staging.signal.org' WHERE server_uuid = '97c17f0c-e53b-426f-8ffa-c052d4183f83';
