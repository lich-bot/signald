/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import io.finn.signald.Account;
import io.finn.signald.db.Database;
import io.finn.signald.db.IKyberPreKeyStore;
import io.sentry.Sentry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.whispersystems.signalservice.api.push.ServiceId;

public class KyberPreKeyTable implements IKyberPreKeyStore {
  private static final Logger logger = LogManager.getLogger();

  private static final String TABLE_NAME = "kyber_prekey_store";
  private final Account account;

  public KyberPreKeyTable(ServiceId.ACI aci) { account = new Account(aci); }

  @Override
  public void deleteAllStaleOneTimeKyberPreKeys(long l, int i) {
    // based on signal-cli:
    // https://github.com/AsamK/signal-cli/blob/375bdb79485ec90beb9a154112821a4657740b7a/lib/src/main/java/org/asamk/signal/manager/storage/prekeys/KyberPreKeyStore.java#L247
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? "
                + "                    AND " + STALE_TIMESTAMP + " < ?"
                + "                    AND " + IS_LAST_RESORT + " = FALSE"
                + "                    AND _id NOT IN ("
                + "                        SELECT _id"
                + "                        FROM " + TABLE_NAME + "                        WHERE " + ACCOUNT_UUID + " = ?"
                + "                        ORDER BY"
                + "                          CASE WHEN " + STALE_TIMESTAMP + " IS NULL THEN 1 ELSE 0 END DESC,"
                + "                          " + STALE_TIMESTAMP + " DESC,"
                + "                          _id DESC"
                + "                        LIMIT ?"
                + "                    )";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      statement.setLong(2, l);
      statement.setString(3, account.getACI().toString());
      statement.setInt(4, i);
      Database.executeUpdate(TABLE_NAME + "_delete_all_stale_one_time_kyber_pre_keys", statement);
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  @NotNull
  @Override
  public List<KyberPreKeyRecord> loadLastResortKyberPreKeys() {
    var query = "SELECT " + KYBER_PREKEY_RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + IS_LAST_RESORT + " = 1";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      ResultSet results = Database.executeQuery(TABLE_NAME + "_load_last_resort_kyber_pre_keys", statement);
      var records = new ArrayList<KyberPreKeyRecord>();
      while (results.next()) {
        byte[] serialized = results.getBytes(1);
        records.add(new KyberPreKeyRecord(serialized));
      }
      return records;
    } catch (SQLException | InvalidMessageException e) {
      logger.error("failed to load last resort kyber prekeys: ", e);
      Sentry.captureException(e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public void markAllOneTimeKyberPreKeysStaleIfNecessary(long l) {}

  @Override
  public void removeKyberPreKey(int i) {}

  @Override
  public void storeLastResortKyberPreKey(int i, @NotNull KyberPreKeyRecord kyberPreKeyRecord) {
    var query = "INSERT INTO " + TABLE_NAME + " (" + ACCOUNT_UUID + "," + KYBER_PREKEY_ID + "," + KYBER_PREKEY_RECORD + "," + IS_LAST_RESORT + ") VALUES (?, ?, ?, ?)";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      statement.setInt(2, i);
      statement.setBytes(3, kyberPreKeyRecord.serialize());
      statement.setInt(4, 1);
      Database.executeUpdate(TABLE_NAME + "_store_last_resort_kyber_pre_key", statement);
    } catch (SQLException e) {
      logger.error("failed to store last resort kyber prekey");
      Sentry.captureException(e);
    }
  }

  @Override
  public void deleteAccount(ServiceId.ACI aci) throws SQLException {
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      Database.executeUpdate(TABLE_NAME + "_delete_account", statement);
    }
  }

  @Override
  public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
    var query = "SELECT " + KYBER_PREKEY_RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + KYBER_PREKEY_ID + " = ? LIMIT 1";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      statement.setInt(2, kyberPreKeyId);
      ResultSet results = Database.executeQuery(TABLE_NAME + "_load_kyber_pre_key", statement);
      if (!results.next()) {
        throw new InvalidKeyIdException("Missing one-time prekey ID: " + kyberPreKeyId);
      }
      byte[] serialized = results.getBytes(1);
      return new KyberPreKeyRecord(serialized);
    } catch (SQLException | InvalidMessageException e) {
      logger.error("failed to load kyber prekey: ", e);
      Sentry.captureException(e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public List<KyberPreKeyRecord> loadKyberPreKeys() {
    var query = "SELECT " + KYBER_PREKEY_RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      ResultSet results = Database.executeQuery(TABLE_NAME + "_load_all_kyber_pre_keys", statement);
      var records = new ArrayList<KyberPreKeyRecord>();
      while (results.next()) {
        byte[] serialized = results.getBytes(1);
        records.add(new KyberPreKeyRecord(serialized));
      }
      return records;
    } catch (SQLException | InvalidMessageException e) {
      logger.error("failed to load kyber prekeys: ", e);
      Sentry.captureException(e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {}

  @Override
  public boolean containsKyberPreKey(int kyberPreKeyId) {
    var query = "SELECT " + KYBER_PREKEY_RECORD + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + KYBER_PREKEY_ID + " = ? LIMIT 1";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      statement.setInt(2, kyberPreKeyId);
      ResultSet results = Database.executeQuery(TABLE_NAME + "_load_kyber_pre_key", statement);
      return results.next();
    } catch (SQLException e) {
      logger.error("failed to load kyber prekey: ", e);
      Sentry.captureException(e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public void markKyberPreKeyUsed(int kyberPreKeyId) {}
}
