/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredential;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Api;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public interface IGroupCredentialsTable {
  Logger logger = LogManager.getLogger();

  String ACCOUNT_UUID = "account_uuid";
  String DATE = "date";
  String CREDENTIAL = "credential";
  String CREDENTIAL_TYPE = "credential_type";

  String CREDENTIAL_TYPE_PNI = "pni";
  String CREDENTIAL_TYPE_CALL_LINK = "call_link";

  void setCredentials(GroupsV2Api.CredentialResponseMaps credentials) throws SQLException;
  void deleteAccount(ACI aci) throws SQLException;
  Optional<AuthCredentialWithPniResponse> getCredential(int date) throws SQLException, InvalidInputException;

  Optional<CallLinkAuthCredential> getCallLinkCredentials(int date) throws SQLException, InvalidInputException;

  default AuthCredentialWithPniResponse getCredential(GroupsV2Api groupsV2Api, int today) throws InvalidInputException, SQLException, IOException {
    Optional<AuthCredentialWithPniResponse> todaysCredentials = this.getCredential(today);
    if (todaysCredentials.isEmpty()) {
      logger.debug("refreshing group credentials");
      setCredentials(groupsV2Api.getCredentials(today));
      todaysCredentials = this.getCredential(today);
    }

    if (todaysCredentials.isEmpty()) {
      throw new IOException("group v2 api credential is empty");
    }

    return todaysCredentials.get();
  }
}
