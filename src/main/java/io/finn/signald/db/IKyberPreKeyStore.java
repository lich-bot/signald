/*
 * Copyright 2023 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.sql.SQLException;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.whispersystems.signalservice.api.SignalServiceKyberPreKeyStore;
import org.whispersystems.signalservice.api.push.ServiceId;

public interface IKyberPreKeyStore extends SignalServiceKyberPreKeyStore {
  String ACCOUNT_UUID = "account_uuid";
  String KYBER_PREKEY_ID = "kyber_prekey_id";
  String KYBER_PREKEY_RECORD = "kyber_prekey_record";
  String IS_LAST_RESORT = "is_last_resort";
  String STALE_TIMESTAMP = "stale_timestamp";

  void deleteAccount(ServiceId.ACI aci) throws SQLException;
}
