/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.sql.SQLException;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public interface ICdsiTable {
  Logger logger = LogManager.getLogger();

  String NUMBER = "number";
  String LAST_SEEN = "last_seen";

  Set<String> allNumbers() throws SQLException;
  void updateAfterFullQuery(Set<String> allNumbers, Set<String> seenNumbers) throws SQLException;
  void updateAfterPartialQuery(Set<String> seenNumbers) throws SQLException;
}
