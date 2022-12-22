ALTER TABLE message_queue DROP COLUMN legacy_message;
ALTER TABLE message_queue ADD COLUMN urgent BOOL DEFAULT FALSE;
ALTER TABLE message_queue ADD COLUMN updated_pni TEXT;
ALTER TABLE message_queue ADD COLUMN story BOOL DEFAULT FALSE;