/*
 * Copyright (C) 2021 Finn Herzfeld
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.finn.signald.db;

import io.finn.signald.BuildConfig;
import io.finn.signald.clientprotocol.v1.JsonAddress;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.storage.AccountData;
import io.finn.signald.util.AddressUtil;
import java.io.File;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public class AccountsTable {
  private static final Logger logger = LogManager.getLogger();
  private static final String TABLE_NAME = "accounts";
  private static final String UUID = "uuid";
  private static final String E164 = "e164";
  private static final String FILENAME = "filename";
  private static final String SERVER = "server";

  public static File getFile(java.util.UUID uuid) throws SQLException, NoSuchAccountException {
    PreparedStatement statement = Database.getConn().prepareStatement("SELECT " + FILENAME + " FROM " + TABLE_NAME + " WHERE " + UUID + " = ?");
    statement.setString(1, uuid.toString());
    ResultSet rows = statement.executeQuery();
    if (!rows.next()) {
      rows.close();
      throw new NoSuchAccountException(uuid.toString());
    }
    String filename = rows.getString(FILENAME);
    rows.close();
    return new File(filename);
  }

  public static File getFile(String e164) throws SQLException, NoSuchAccountException {
    PreparedStatement statement = Database.getConn().prepareStatement("SELECT " + FILENAME + " FROM " + TABLE_NAME + " WHERE " + E164 + " = ?");
    statement.setString(1, e164);
    ResultSet rows = statement.executeQuery();
    if (!rows.next()) {
      rows.close();
      throw new NoSuchAccountException(e164);
    }
    String filename = rows.getString(FILENAME);
    rows.close();
    return new File(filename);
  }

  public static void add(String e164, java.util.UUID uuid, String filename, java.util.UUID server) throws SQLException {
    PreparedStatement statement =
        Database.getConn().prepareStatement("INSERT OR IGNORE INTO " + TABLE_NAME + " (" + UUID + "," + E164 + "," + FILENAME + "," + SERVER + ") VALUES (?, ?, ?, ?)");
    statement.setString(1, uuid.toString());
    if (e164 != null) {
      statement.setString(2, e164);
    }
    statement.setString(3, filename);
    statement.setString(4, server == null ? null : server.toString());
    statement.executeUpdate();
    AddressUtil.addKnownAddress(new SignalServiceAddress(uuid, e164));
  }

  public static void importFromJSON(File f) throws IOException, SQLException {
    AccountData accountData = AccountData.load(f);
    logger.info("migrating account if needed: " + accountData.address.toRedactedString());
    add(accountData.username, accountData.getUUID(), f.getAbsolutePath(), java.util.UUID.fromString(BuildConfig.DEFAULT_SERVER_UUID));
    boolean needsSave = false;
    try {
      if (accountData.legacyProtocolStore != null) {
        accountData.legacyProtocolStore.migrateToDB(accountData.getUUID());
        accountData.legacyProtocolStore = null;
        needsSave = true;
      }
      if (accountData.legacyRecipientStore != null) {
        accountData.legacyRecipientStore.migrateToDB(accountData.getUUID());
        accountData.legacyRecipientStore = null;
        needsSave = true;
      }

      if (accountData.backgroundActionsLastRun != null) {
        accountData.backgroundActionsLastRun.migrateToDB(accountData.getUUID());
        accountData.backgroundActionsLastRun = null;
        needsSave = true;
      }
    } finally {
      if (needsSave) {
        accountData.save();
      }
    }
  }

  public static void deleteAccount(java.util.UUID uuid) throws SQLException {
    PreparedStatement statement = Database.getConn().prepareStatement("DELETE FROM " + TABLE_NAME + " WHERE " + UUID + " = ?");
    statement.setString(1, uuid.toString());
    statement.executeUpdate();
  }

  public static void setUUID(JsonAddress address) throws SQLException {
    assert address.uuid != null;
    assert address.number != null;
    PreparedStatement statement = Database.getConn().prepareStatement("UPDATE " + TABLE_NAME + " SET " + UUID + " = ? WHERE " + E164 + " = ?");
    statement.setString(1, address.uuid);
    statement.setString(2, address.number);
    statement.executeUpdate();
  }

  public static java.util.UUID getUUID(String e164) throws SQLException, NoSuchAccountException {
    PreparedStatement statement = Database.getConn().prepareStatement("SELECT " + UUID + " FROM " + TABLE_NAME + " WHERE " + E164 + " = ?");
    statement.setString(1, e164);
    ResultSet rows = statement.executeQuery();
    if (!rows.next()) {
      rows.close();
      throw new NoSuchAccountException(e164);
    }
    java.util.UUID result = java.util.UUID.fromString(rows.getString(UUID));
    rows.close();
    return result;
  }

  public static ServersTable.Server getServer(java.util.UUID uuid) throws SQLException, IOException, ServerNotFoundException, InvalidProxyException {
    PreparedStatement statement = Database.getConn().prepareStatement("SELECT " + SERVER + " FROM " + TABLE_NAME + " WHERE " + UUID + " = ?");
    statement.setString(1, uuid.toString());
    ResultSet rows = statement.executeQuery();
    if (!rows.next()) {
      rows.close();
      throw new AssertionError("account not found");
    }
    String serverUUID = rows.getString(SERVER);
    rows.close();
    if (serverUUID == null) {
      serverUUID = BuildConfig.DEFAULT_SERVER_UUID;
      setServer(uuid, serverUUID);
    }
    return ServersTable.getServer(java.util.UUID.fromString(serverUUID));
  }

  private static void setServer(java.util.UUID account, String server) throws SQLException {
    PreparedStatement statement = Database.getConn().prepareStatement("UPDATE " + TABLE_NAME + " SET " + SERVER + " = ? WHERE " + UUID + " = ?");
    statement.setString(1, server);
    statement.setString(2, account.toString());
    statement.executeUpdate();
  }
}
