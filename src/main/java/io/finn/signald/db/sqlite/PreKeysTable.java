/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import io.finn.signald.db.Database;
import io.finn.signald.db.IPreKeysTable;
import io.sentry.Sentry;
import java.sql.SQLException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public class PreKeysTable implements IPreKeysTable {
  private static final Logger logger = LogManager.getLogger();
  private static final String TABLE_NAME = "prekeys";
  private final ACI aci;

  public PreKeysTable(ACI aci) { this.aci = aci; }

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    try {
      var query = "SELECT " + RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + ID + " = ?";
      try (var statement = Database.getConn().prepareStatement(query)) {
        statement.setString(1, aci.toString());
        statement.setInt(2, preKeyId);
        try (var rows = Database.executeQuery(TABLE_NAME + "_load_pre_key", statement)) {
          if (!rows.next()) {
            throw new InvalidKeyIdException("prekey not found");
          }
          return new PreKeyRecord(rows.getBytes(RECORD));
        }
      }
    } catch (SQLException | InvalidMessageException t) {
      throw new InvalidKeyIdException(t);
    }
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    try {
      var query = "INSERT OR REPLACE INTO " + TABLE_NAME + "(" + ACCOUNT_UUID + "," + ID + "," + RECORD + ") VALUES (?, ?, ?);";
      try (var statement = Database.getConn().prepareStatement(query)) {
        statement.setString(1, aci.toString());
        statement.setInt(2, preKeyId);
        statement.setBytes(3, record.serialize());
        Database.executeUpdate(TABLE_NAME + "_store_pre_key", statement);
      }
    } catch (SQLException e) {
      logger.error("failed to store prekey", e);
      Sentry.captureException(e);
    }
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    try {
      var query = "SELECT " + RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + ID + " = ?";
      try (var statement = Database.getConn().prepareStatement(query)) {
        statement.setString(1, aci.toString());
        statement.setInt(2, preKeyId);
        try (var rows = Database.executeQuery(TABLE_NAME + "_contains_pre_key", statement)) {
          return rows.next();
        }
      }
    } catch (SQLException e) {
      logger.error("failed to check if prekey exists", e);
      Sentry.captureException(e);
      return false;
    }
  }

  @Override
  public void removePreKey(int preKeyId) {
    try {
      var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + ID + " = ?";
      try (var statement = Database.getConn().prepareStatement(query)) {
        statement.setString(1, aci.toString());
        statement.setInt(2, preKeyId);
        Database.executeUpdate(TABLE_NAME + "_remove_pre_key", statement);
      }
    } catch (SQLException e) {
      logger.error("failed to delete prekey", e);
      Sentry.captureException(e);
    }
  }

  @Override
  public void deleteAccount(ACI aci) throws SQLException {
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, aci.toString());
      Database.executeUpdate(TABLE_NAME + "_delete_account", statement);
    }
  }

  @Override
  public void deleteAllStaleOneTimeEcPreKeys(long threshold, int minRemaining) {
    // based on Signal-Android:
    // https://github.com/signalapp/Signal-Android/blob/e17b07bb12110c0ebeae193cb6fad35d33b57d40/app/src/main/java/org/thoughtcrime/securesms/database/OneTimePreKeyTable.kt#L89
    // and signal-cli:
    // https://github.com/AsamK/signal-cli/blob/375bdb79485ec90beb9a154112821a4657740b7a/lib/src/main/java/org/asamk/signal/manager/storage/prekeys/PreKeyStore.java#L188
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + STALE_TIMESTAMP + " > 0 AND " + STALE_TIMESTAMP + " < ? AND _id NOT IN ("
                + "SELECT _id FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? ORDER BY "
                + "CASE " + STALE_TIMESTAMP + " IS NULL THEN 1 ELSE 0 END DESC, " + STALE_TIMESTAMP + " DESC, "
                + "_id DESC, LIMIT ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, aci.toString());
      statement.setLong(2, threshold);
      statement.setString(3, aci.toString());
      statement.setInt(4, minRemaining);
      Database.executeUpdate(TABLE_NAME + "_delete_all_stale_one_time_ec_pre_keys", statement);
    } catch (SQLException e) {
      logger.error("failed to mark all one-time ec prekeys stale");
      Sentry.captureException(e);
    }
  }

  @Override
  public void markAllOneTimeEcPreKeysStaleIfNecessary(long timestamp) {
    var query = "UPDATE " + TABLE_NAME + " SET " + STALE_TIMESTAMP + " = ? WHERE " + ACCOUNT_UUID + " = ? AND " + STALE_TIMESTAMP + " IS NULL";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setLong(1, timestamp);
      statement.setString(2, aci.toString());
      Database.executeUpdate(TABLE_NAME + "_mark_all_one_time_ec_pre_keys_stale_if_necessary", statement);
    } catch (SQLException e) {
      logger.error("failed to mark all one-time ec prekeys stale");
      Sentry.captureException(e);
    }
  }
}
