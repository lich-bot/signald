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

package io.finn.signald;

import io.finn.signald.db.AccountDataTable;
import io.finn.signald.db.AccountsTable;
import io.finn.signald.db.PendingAccountDataTable;
import io.finn.signald.db.ServersTable;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.storage.AccountData;
import io.finn.signald.util.GroupsUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.zkgroup.InvalidInputException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Operations;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.internal.ServiceResponse;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.push.VerifyAccountResponse;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class RegistrationManager {
  private final static Logger logger = LogManager.getLogger();
  private static final ConcurrentHashMap<String, RegistrationManager> registrationManagers = new ConcurrentHashMap<>();

  private final SignalServiceConfiguration serviceConfiguration;
  private final SignalServiceAccountManager accountManager;
  private final ECPublicKey unidentifiedSenderTrustRoot;
  private final AccountData accountData;

  public static RegistrationManager get(String e164, UUID server) throws IOException, SQLException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    Logger logger = LogManager.getLogger("registration-manager");
    String key = getKey(e164, server);
    if (registrationManagers.containsKey(key)) {
      return registrationManagers.get(key);
    }
    RegistrationManager m = new RegistrationManager(e164, server);
    registrationManagers.put(key, m);
    logger.info("Created a registration manager for " + Util.redact(e164));
    return m;
  }

  RegistrationManager(String e164, UUID serverUUID) throws SQLException, ServerNotFoundException, InvalidProxyException, IOException, InvalidKeyException {
    ServersTable.Server server = ServersTable.getServer(serverUUID);
    serviceConfiguration = server.getSignalServiceConfiguration();
    unidentifiedSenderTrustRoot = server.getUnidentifiedSenderRoot();
    accountData = new AccountData(e164);

    DynamicCredentialsProvider credentialProvider = new DynamicCredentialsProvider(null, e164, accountData.password, SignalServiceAddress.DEFAULT_DEVICE_ID);
    GroupsV2Operations groupsV2Operations = GroupsUtil.GetGroupsV2Operations(serviceConfiguration);
    accountManager = new SignalServiceAccountManager(serviceConfiguration, credentialProvider, BuildConfig.USER_AGENT, groupsV2Operations, ServiceConfig.AUTOMATIC_NETWORK_RETRY);
  }

  public void register(boolean voiceVerification, Optional<String> captcha) throws IOException, InvalidInputException {
    accountData.password = Util.getSecret(18);

    if (voiceVerification) {
      accountManager.requestVoiceVerificationCode(Locale.getDefault(), captcha, Optional.absent(), Optional.absent());
    } else {
      accountManager.requestSmsVerificationCode(false, captcha, Optional.absent(), Optional.absent());
    }

    accountData.registered = false;
    accountData.init();
    accountData.save();
  }

  public Manager verifyAccount(String verificationCode)
      throws IOException, InvalidInputException, SQLException, InvalidProxyException, InvalidKeyException, ServerNotFoundException {
    verificationCode = verificationCode.replace("-", "");
    accountData.signalingKey = Util.getSecret(52); // TODO: check if this is this is still needed
    int registrationID = PendingAccountDataTable.getInt(accountData.username, PendingAccountDataTable.Key.LOCAL_REGISTRATION_ID);
    ServiceResponse<VerifyAccountResponse> r =
        accountManager.verifyAccount(verificationCode, registrationID, true, accountData.getSelfUnidentifiedAccessKey(), false, ServiceConfig.CAPABILITIES, true);
    VerifyAccountResponse result = r.getResult().get();
    accountData.setUUID(UUID.fromString(result.getUuid()));
    String server = PendingAccountDataTable.getString(accountData.username, PendingAccountDataTable.Key.SERVER_UUID);
    AccountsTable.add(accountData.address.number, accountData.address.getUUID(), getFileName(), server == null ? null : UUID.fromString(server));
    accountData.save();

    AccountDataTable.set(accountData.address.getUUID(), AccountDataTable.Key.LOCAL_REGISTRATION_ID, registrationID);

    byte[] identityKeyPair = PendingAccountDataTable.getBytes(accountData.username, PendingAccountDataTable.Key.LOCAL_REGISTRATION_ID);
    AccountDataTable.set(accountData.address.getUUID(), AccountDataTable.Key.OWN_IDENTITY_KEY_PAIR, identityKeyPair);
    PendingAccountDataTable.clear(accountData.username);
    accountData.registered = true;
    accountData.init();
    accountData.save();

    Manager m = new Manager(accountData);
    m.refreshPreKeys();

    return m;
  }

  public String getE164() { return accountData.username; }

  private String getFileName() { return Manager.getFileName(accountData.username); }

  public boolean hasPendingKeys() throws SQLException { return PendingAccountDataTable.getBytes(accountData.username, PendingAccountDataTable.Key.OWN_IDENTITY_KEY_PAIR) != null; }

  public boolean isRegistered() { return accountData.registered; }

  private static String getKey(String e164, UUID server) { return e164 + server.toString(); }
}
