/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.postgresql;

import io.finn.signald.Account;
import io.finn.signald.db.ICdsiTable;
import java.sql.SQLException;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.whispersystems.signalservice.api.push.ServiceId;

public class CdsiTable implements ICdsiTable {
  private static final Logger logger = LogManager.getLogger();
  private static final String TABLE_NAME = "signald_cdsi";
  private final Account account;

  public CdsiTable(ServiceId.ACI aci) { account = new Account(aci); }

  @Override
  public Set<String> allNumbers() throws SQLException {
    return null;
  }

  @Override
  public void updateAfterFullQuery(Set<String> allNumbers, Set<String> seenNumbers) throws SQLException {}

  @Override
  public void updateAfterPartialQuery(Set<String> seenNumbers) throws SQLException {}
}
