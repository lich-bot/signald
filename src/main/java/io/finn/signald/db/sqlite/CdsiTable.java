/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.sqlite;

import io.finn.signald.Account;
import io.finn.signald.db.Database;
import io.finn.signald.db.ICdsiTable;
import io.sentry.Sentry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.whispersystems.signalservice.api.push.ServiceId;

public class CdsiTable implements ICdsiTable {
  private static final Logger logger = LogManager.getLogger();
  private static final String TABLE_NAME = "cdsi";
  private final Account account;

  public CdsiTable(ServiceId.ACI aci) { account = new Account(aci); }

  @Override
  public Set<String> allNumbers() throws SQLException {
    var query = "SELECT " + NUMBER + " FROM " + TABLE_NAME;
    try (var statement = Database.getConn().prepareStatement(query)) {
      statement.setString(1, account.getACI().toString());
      ResultSet results = Database.executeQuery(TABLE_NAME + "_get_all", statement);
      var records = new HashSet<String>();
      while (results.next()) {
        records.add(results.getString(1));
      }
      return records;
    }
  }

  @Override
  public void updateAfterFullQuery(Set<String> allNumbers, Set<String> seenNumbers) throws SQLException {}

  @Override
  public void updateAfterPartialQuery(Set<String> seenNumbers) throws SQLException {}
}
