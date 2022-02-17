/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import io.finn.signald.SignalDependencies;
import io.finn.signald.db.Database;
import io.finn.signald.db.IRecipientsTable;
import io.finn.signald.db.Recipient;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.sentry.Sentry;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.signalservice.api.push.ACI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.internal.contacts.crypto.Quote;
import org.whispersystems.signalservice.internal.contacts.crypto.UnauthenticatedQuoteException;
import org.whispersystems.signalservice.internal.contacts.crypto.UnauthenticatedResponseException;

public class RecipientsTable implements IRecipientsTable {
  private static final Logger logger = LogManager.getLogger();

  static final String TABLE_NAME = "recipients";

  private final UUID uuid;

  public RecipientsTable(java.util.UUID u) { uuid = u; }

  public RecipientsTable(ACI aci) { uuid = aci.uuid(); }

  public Recipient get(String e164, ACI aci) throws SQLException, IOException {
    List<Recipient> results = new ArrayList<>();
    var query = "SELECT " + ROW_ID + "," + E164 + "," + UUID + " FROM " + TABLE_NAME + " WHERE (" + UUID + " = ? OR " + E164 + " = ?) AND " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      if (aci != null) {
        statement.setString(1, aci.toString());
      }

      if (e164 != null) {
        statement.setString(2, e164);
      }

      statement.setString(3, uuid.toString());
      try (var rows = Database.executeQuery(TABLE_NAME + "_get", statement)) {
        while (rows.next()) {
          int rowid = rows.getInt(ROW_ID);
          String storedE164 = rows.getString(E164);
          String storedUUID = rows.getString(UUID);
          SignalServiceAddress a = storedUUID == null ? null : new SignalServiceAddress(ACI.from(java.util.UUID.fromString(storedUUID)), storedE164);
          results.add(new Recipient(uuid, rowid, a));
        }
      }
    }

    int rowid = -1;
    ACI storedACI = null;
    String storedE164 = null;
    if (results.size() > 0) {
      Recipient result = results.get(0);
      rowid = result.getId();

      if (results.size() > 1) {
        logger.warn("recipient query returned multiple results, merging");
        for (Recipient r : results) {
          if (rowid < 0 && r.getAddress() != null) { // have not selected a preferred winner yet and this candidate has a UUID
            rowid = r.getId();
            result = r;
          } else {
            logger.debug("Dropping duplicate recipient row id = " + rowid);
            delete(r.getId());
          }
        }
      }

      storedACI = result.getAddress() != null ? result.getACI() : null;
      storedE164 = result.getAddress() != null ? result.getAddress().getNumber().orNull() : null;
      rowid = result.getId();
    }

    // query included a UUID that wasn't in the database
    if (aci != null && storedACI == null) {
      if (rowid < 0) {
        rowid = storeNew(aci, e164);
        storedE164 = e164;
      } else {
        update(UUID, aci.toString(), rowid);
      }
      storedACI = aci;
    }

    // query included an e164 that wasn't in the database
    if (e164 != null && rowid > -1 && storedE164 == null) {
      update(E164, e164, rowid);
      storedE164 = e164;
    }

    if (e164 != null && !e164.equals(storedE164)) {
      // phone number change
      // TODO: notify clients?
      update(E164, e164, rowid);
    }

    // query did not include a UUID
    if (storedACI == null) {
      // ask the server for the UUID (throws UnregisteredUserException if the e164 isn't registered)
      storedACI = getRegisteredUser(e164);

      if (rowid > 0) {
        // if the e164 was in the database already, update the existing row
        update(UUID, storedACI.toString(), rowid);
      } else {
        // if the e164 was not in the database, re-run the get() with both e164 and UUID
        // can't just insert because the newly-discovered UUID might already be in the database
        return get(e164, storedACI);
      }
    }

    if (rowid == -1 && aci != null) {
      rowid = storeNew(aci, e164);
    }

    return new Recipient(uuid, rowid, new SignalServiceAddress(storedACI, storedE164));
  }

  private int storeNew(ACI aci, String e164) throws SQLException {
    var query = "INSERT INTO " + TABLE_NAME + "(" + ACCOUNT_UUID + "," + UUID + "," + E164 + ") VALUES (?, ?, ?)";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, uuid.toString());
      statement.setString(2, aci.toString());
      if (e164 != null) {
        statement.setString(3, e164);
      }
      Database.executeUpdate(TABLE_NAME + "_store_name", statement);
    }
    try (var statement = Database.getConn().prepareStatement("SELECT last_insert_rowid()")) {
      try (var rows = Database.executeQuery(TABLE_NAME + "_get_stored", statement)) {
        if (!rows.next()) {
          throw new AssertionError("error fetching ID of last row inserted while storing " + aci + "/" + e164);
        }
        return rows.getInt(1);
      }
    }
  }

  private void update(String column, String value, int row) throws SQLException {
    var query = "UPDATE " + TABLE_NAME + " SET " + column + " = ? WHERE " + ACCOUNT_UUID + " = ? AND " + ROW_ID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, value);
      statement.setString(2, uuid.toString());
      statement.setInt(3, row);
      Database.executeUpdate(TABLE_NAME + "_update", statement);
    }
  }

  private void delete(int row)throws SQLException {
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ROW_ID + " = ? AND " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setInt(1, row);
      statement.setString(2, uuid.toString());
      Database.executeUpdate(TABLE_NAME + "_delete", statement);
    }
  }

  @Override
  public void deleteAccount(UUID uuid) throws SQLException {
    var query = "DELETE FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ?";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, uuid.toString());
      Database.executeUpdate(TABLE_NAME + "_delete_account", statement);
    }
  }

  private ACI getRegisteredUser(final String number) throws IOException, SQLException {
    final Map<String, ACI> aciMap;
    try {
      Set<String> numbers = new HashSet<>();
      numbers.add(number);
      aciMap = getRegisteredUsers(numbers);
    } catch (NumberFormatException e) {
      throw new UnregisteredUserException(number, e);
    } catch (InvalidProxyException | ServerNotFoundException | NoSuchAccountException e) {
      logger.error("error resolving UUIDs: ", e);
      Sentry.captureException(e);
      throw new IOException(e);
    }
    ACI aci = aciMap.get(number);
    if (aci == null) {
      throw new UnregisteredUserException(number, null);
    }
    return aci;
  }

  private Map<String, ACI> getRegisteredUsers(final Set<String> numbers) throws IOException, InvalidProxyException, SQLException, ServerNotFoundException, NoSuchAccountException {
    var server = Database.Get().AccountsTable.getServer(uuid);
    var accountManager = SignalDependencies.get(uuid).getAccountManager();
    logger.debug("querying server for UUIDs of " + numbers.size() + " e164 identifiers");
    try {
      return accountManager.getRegisteredUsers(server.getIASKeyStore(), numbers, server.getCdsMrenclave());
    } catch (InvalidKeyException | KeyStoreException | CertificateException | NoSuchAlgorithmException | Quote.InvalidQuoteFormatException | UnauthenticatedQuoteException |
             SignatureException | UnauthenticatedResponseException e) {
      throw new IOException(e);
    }
  }
}