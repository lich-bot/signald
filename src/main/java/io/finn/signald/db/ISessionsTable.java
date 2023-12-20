/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SessionStore;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public interface ISessionsTable extends SessionStore {
  String ROW_ID = "rowid";
  String ACCOUNT_UUID = "account_uuid";
  String RECIPIENT = "recipient";
  String DEVICE_ID = "device_id";
  String RECORD = "record";

  void deleteAccount(ACI aci) throws SQLException;
  Map<SignalProtocolAddress, SessionRecord> getAllAddressesWithActiveSessions(List<String> list);
  void archiveAllSessions(Recipient recipient) throws SQLException;

  default void deleteAllSessions(Recipient recipient) { deleteAllSessions(recipient.getAddress().getIdentifier()); }
}
