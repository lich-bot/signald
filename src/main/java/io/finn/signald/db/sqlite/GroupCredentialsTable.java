/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import io.finn.signald.db.Database;
import io.finn.signald.db.IGroupCredentialsTable;
import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredential;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Api;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public class GroupCredentialsTable implements IGroupCredentialsTable {
  private static final String TABLE_NAME = "group_credentials";

  private final ACI aci;

  public GroupCredentialsTable(ACI aci) { this.aci = aci; }

  @Override
  public Optional<AuthCredentialWithPniResponse> getCredential(int date) throws SQLException, InvalidInputException {
    var query = "SELECT " + CREDENTIAL + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + DATE + " = ? AND " + CREDENTIAL_TYPE + " = '" + CREDENTIAL_TYPE_PNI + "'";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, aci.toString());
      statement.setInt(2, date);
      try (var rows = Database.executeQuery(TABLE_NAME + "_get_credential", statement)) {
        return rows.next() ? Optional.of(new AuthCredentialWithPniResponse(rows.getBytes(CREDENTIAL))) : Optional.empty();
      }
    }
  }

  @Override
  public Optional<CallLinkAuthCredential> getCallLinkCredentials(int date) throws SQLException, InvalidInputException {
    var query = "SELECT " + CREDENTIAL + " FROM " + TABLE_NAME + " WHERE " + ACCOUNT_UUID + " = ? AND " + DATE + " = ? AND " + CREDENTIAL_TYPE + " = '" + CREDENTIAL_TYPE_PNI + "'";
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, aci.toString());
      statement.setInt(2, date);
      try (var rows = Database.executeQuery(TABLE_NAME + "_get_credential", statement)) {
        return rows.next() ? Optional.of(new CallLinkAuthCredential(rows.getBytes(CREDENTIAL))) : Optional.empty();
      }
    }
  }

  @Override
  public void setCredentials(GroupsV2Api.CredentialResponseMaps credentials) throws SQLException {
    var query = "INSERT OR REPLACE INTO " + TABLE_NAME + " (" + ACCOUNT_UUID + "," + DATE + "," + CREDENTIAL + "," + CREDENTIAL_TYPE + ") VALUES (?, ?, ?, ?)";
    try (var statement = Database.getConn().prepareStatement(query)) {
      for (Map.Entry<Long, AuthCredentialWithPniResponse> entry : credentials.getAuthCredentialWithPniResponseHashMap().entrySet()) {
        statement.setString(1, aci.toString());
        statement.setLong(2, entry.getKey());
        statement.setBytes(3, entry.getValue().serialize());
        statement.setString(4, CREDENTIAL_TYPE_PNI);
        statement.addBatch();
      }
      for (var entry : credentials.getCallLinkAuthCredentialResponseHashMap().entrySet()) {
        statement.setString(1, aci.toString());
        statement.setLong(2, entry.getKey());
        statement.setBytes(3, entry.getValue().serialize());
        statement.setString(4, CREDENTIAL_TYPE_CALL_LINK);
        statement.addBatch();
      }
      Database.executeBatch(TABLE_NAME + "_set_credentials", statement);
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
}
