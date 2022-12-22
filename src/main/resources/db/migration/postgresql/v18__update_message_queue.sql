ALTER TABLE signald_message_queue DROP COLUMN legacy_message;
ALTER TABLE signald_message_queue ADD COLUMN urgent BOOL DEFAULT FALSE;
ALTER TABLE signald_message_queue ADD COLUMN updated_pni VARCHAR(100); -- TODO: figure out the correct size
ALTER TABLE signald_message_queue ADD COLUMN story BOOL DEFAULT FALSE;