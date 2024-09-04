/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import static org.junit.jupiter.api.Assertions.*;

import io.finn.signald.db.Database;
import io.finn.signald.db.IMessageQueueTable;
import io.finn.signald.db.StoredEnvelope;
import io.finn.signald.db.TestUtil;
import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

class MessageQueueTableTest {
  private static final ACI ACCOUNT_ACI = ACI.from(UUID.fromString("00000000-0000-4000-0000-000000000000"));
  private static final int TYPE_UNIDENTIFIED_SENDER = 6;

  private IMessageQueueTable messageQueue;
  private File databaseFile;

  @BeforeEach
  void setUp() throws IOException {
    databaseFile = TestUtil.createAndConfigureTestSQLiteDatabase();
    messageQueue = Database.Get(ACCOUNT_ACI).MessageQueueTable;
  }

  @AfterEach
  void tearDown() {
    Database.close();
    if (!databaseFile.delete()) {
      System.err.println("Test database file couldn't be deleted: " + databaseFile.getAbsolutePath());
    }
  }

  @Test
  @DisplayName("nextEnvelope() with unidentified sender type")
  void nextEnvelope_withUnidentifiedSender() throws SQLException {
    int type = TYPE_UNIDENTIFIED_SENDER;

    int senderDevice = 0;
    long timestamp = 100L;
    byte[] content = {1};
    long serverReceivedTimestamp = 200L;
    long serverDeliveredTimestamp = 300L;
    String uuid = UUID.randomUUID().toString();

    boolean urgent = false;
    boolean story = false;

    SignalServiceEnvelope originalEnvelope =
        new SignalServiceEnvelope(type, timestamp, content, serverReceivedTimestamp, serverDeliveredTimestamp, uuid, ACCOUNT_ACI.toString(), urgent, story, null, null);
    messageQueue.storeEnvelope(originalEnvelope);

    StoredEnvelope storedEnvelope = messageQueue.nextEnvelope();

    SignalServiceEnvelope envelope = storedEnvelope.envelope;
    assertEquals(type, envelope.getType());
    assertEquals(senderDevice, envelope.getSourceDevice());
    assertEquals(timestamp, envelope.getTimestamp());
    assertArrayEquals(content, envelope.getContent());
    assertEquals(serverReceivedTimestamp, envelope.getServerReceivedTimestamp());
    assertEquals(serverDeliveredTimestamp, envelope.getServerDeliveredTimestamp());
    assertEquals(uuid, envelope.getServerGuid());
  }

  @Test
  @DisplayName("deleteEnvelope() should only remove one entry from the message queue")
  void deleteEnvelope_onlyOneRow() throws SQLException {
    byte[] content1 = {1};
    byte[] content2 = {2};
    SignalServiceEnvelope envelope1 = createUnidentifiedSenderSignalServiceEnvelope(content1);
    SignalServiceEnvelope envelope2 = createUnidentifiedSenderSignalServiceEnvelope(content2);
    long databaseId1 = messageQueue.storeEnvelope(envelope1);
    long databaseId2 = messageQueue.storeEnvelope(envelope2);

    StoredEnvelope storedEnvelope = messageQueue.nextEnvelope();
    assertEquals(databaseId1, storedEnvelope.databaseId);
    messageQueue.deleteEnvelope(storedEnvelope.databaseId);

    StoredEnvelope secondStoredEnvelope = messageQueue.nextEnvelope();
    assertNotNull(secondStoredEnvelope, "Expected second envelope not found in message queue");
    assertEquals(databaseId2, secondStoredEnvelope.databaseId);
    assertArrayEquals(content2, secondStoredEnvelope.envelope.getContent());
  }

  private SignalServiceEnvelope createUnidentifiedSenderSignalServiceEnvelope(byte[] content) {
    long timestamp = 100L;
    long serverReceivedTimestamp = 200L;
    long serverDeliveredTimestamp = 300L;
    String uuid = UUID.randomUUID().toString();

    return new SignalServiceEnvelope(TYPE_UNIDENTIFIED_SENDER, timestamp, content, serverReceivedTimestamp, serverDeliveredTimestamp, uuid, ACCOUNT_ACI.toString(), false, false,
                                     null, null);
  }
}
