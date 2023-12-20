/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialResponse;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredentialResponse;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Api;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public interface IGroupCredentialsTable {
  Logger logger = LogManager.getLogger();

  String ACCOUNT_UUID = "account_uuid";
  String DATE = "date";
  String CREDENTIAL = "credential";

  void setCredentials(GroupsV2Api.CredentialResponseMaps credentials) throws SQLException;
  void deleteAccount(ACI aci) throws SQLException;
  Optional<GroupsV2Api.CredentialResponseMaps> getCredential(int date) throws SQLException, InvalidInputException;

  default GroupsV2Api.CredentialResponseMaps getCredential(GroupsV2Api groupsV2Api, int today) throws InvalidInputException, SQLException, IOException {
    Optional<GroupsV2Api.CredentialResponseMaps> todaysCredentials = getCredential(today);
    if (todaysCredentials.isEmpty()) {
      logger.debug("refreshing group credentials");
      setCredentials(groupsV2Api.getCredentials(today));
      todaysCredentials = getCredential(today);
    }
    return todaysCredentials.get();
  }
}
