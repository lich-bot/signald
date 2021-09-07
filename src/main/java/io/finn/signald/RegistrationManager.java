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
import io.finn.signald.util.KeyUtil;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asamk.signal.util.RandomUtils;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.profiles.ProfileKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Operations;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.internal.ServiceResponse;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.push.VerifyAccountResponse;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;

public class RegistrationManager {
  private final static Logger logger = LogManager.getLogger();
  private static final ConcurrentHashMap<String, RegistrationManager> registrationManagers = new ConcurrentHashMap<>();

  private final SignalServiceConfiguration serviceConfiguration;
  private final SignalServiceAccountManager accountManager;
  private final AccountData accountData;
  private final String e164;

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

  RegistrationManager(String e164, UUID serverUUID) throws SQLException, ServerNotFoundException, InvalidProxyException, IOException {
    this.e164 = e164;
    ServersTable.Server server = ServersTable.getServer(serverUUID);
    serviceConfiguration = server.getSignalServiceConfiguration();
    accountData = new AccountData(e164);
    accountData.registered = false;

    DynamicCredentialsProvider credentialProvider = new DynamicCredentialsProvider(null, e164, null, SignalServiceAddress.DEFAULT_DEVICE_ID);
    GroupsV2Operations groupsV2Operations = GroupsUtil.GetGroupsV2Operations(serviceConfiguration);
    accountManager = new SignalServiceAccountManager(serviceConfiguration, credentialProvider, BuildConfig.USER_AGENT, groupsV2Operations, ServiceConfig.AUTOMATIC_NETWORK_RETRY);
  }

  public void register(boolean voiceVerification, Optional<String> captcha, UUID server) throws IOException, InvalidInputException, SQLException {
    PendingAccountDataTable.set(e164, PendingAccountDataTable.Key.LOCAL_REGISTRATION_ID, KeyUtil.generateIdentityKeyPair().serialize());
    PendingAccountDataTable.set(e164, PendingAccountDataTable.Key.OWN_IDENTITY_KEY_PAIR, KeyHelper.generateRegistrationId(false));
    PendingAccountDataTable.set(e164, PendingAccountDataTable.Key.SERVER_UUID, server.toString());

    if (voiceVerification) {
      accountManager.requestVoiceVerificationCode(Locale.getDefault(), captcha, Optional.absent(), Optional.absent());
    } else {
      accountManager.requestSmsVerificationCode(false, captcha, Optional.absent(), Optional.absent());
    }

    accountData.init();
    accountData.save();
  }

  public Manager verifyAccount(String verificationCode)
      throws IOException, InvalidInputException, SQLException, InvalidProxyException, InvalidKeyException, ServerNotFoundException {
    verificationCode = verificationCode.replace("-", "");
    int registrationID = PendingAccountDataTable.getInt(e164, PendingAccountDataTable.Key.LOCAL_REGISTRATION_ID);
    byte[] key = new byte[32];
    RandomUtils.getSecureRandom().nextBytes(key);
    ProfileKey profileKey = new ProfileKey(key);
    byte[] selfUnidentifiedAccessKey = UnidentifiedAccess.deriveAccessKeyFrom(profileKey);
    ServiceResponse<VerifyAccountResponse> r =
        accountManager.verifyAccount(verificationCode, registrationID, true, selfUnidentifiedAccessKey, false, ServiceConfig.CAPABILITIES, true);

    final var throwableOptional = r.getExecutionError().or(r.getApplicationError());
    if (throwableOptional.isPresent()) {
      if (throwableOptional.get() instanceof IOException) {
        throw(IOException) throwableOptional.get();
      } else {
        throw new IOException(throwableOptional.get());
      }
    }

    VerifyAccountResponse result = r.getResult().get();
    UUID accountUUID = UUID.fromString(result.getUuid());
    accountData.setUUID(accountUUID);
    accountData.setProfileKey(profileKey);
    String server = PendingAccountDataTable.getString(e164, PendingAccountDataTable.Key.SERVER_UUID);
    AccountsTable.add(e164, accountUUID, getFileName(), server == null ? null : UUID.fromString(server));
    accountData.save();

    AccountDataTable.set(accountUUID, AccountDataTable.Key.LOCAL_REGISTRATION_ID, registrationID);

    byte[] identityKeyPair = PendingAccountDataTable.getBytes(e164, PendingAccountDataTable.Key.LOCAL_REGISTRATION_ID);
    AccountDataTable.set(accountUUID, AccountDataTable.Key.OWN_IDENTITY_KEY_PAIR, identityKeyPair);
    PendingAccountDataTable.clear(e164);
    accountData.registered = true;
    accountData.init();
    accountData.save();

    Manager m = new Manager(accountUUID, accountData);
    m.refreshPreKeys();

    return m;
  }

  public String getE164() { return e164; }

  private String getFileName() { return Manager.getFileName(e164); }

  public boolean hasPendingKeys() throws SQLException { return PendingAccountDataTable.getBytes(e164, PendingAccountDataTable.Key.OWN_IDENTITY_KEY_PAIR) != null; }

  public boolean isRegistered() { return accountData.registered; }

  private static String getKey(String e164, UUID server) { return e164 + server.toString(); }
}
