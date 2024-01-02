/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.sql.SQLException;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.whispersystems.signalservice.api.SignalServicePreKeyStore;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public interface IPreKeysTable extends SignalServicePreKeyStore {
  String ACCOUNT_UUID = "account_uuid";
  String ID = "id";
  String RECORD = "record";
  String STALE_TIMESTAMP = "stale_timestamp";

  void deleteAccount(ACI aci) throws SQLException;
}
