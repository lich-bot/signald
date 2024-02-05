/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import io.finn.signald.db.Database;
import io.finn.signald.db.IAccountDataTable;
import io.finn.signald.db.IPendingAccountDataTable;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.util.GroupsUtil;
import io.finn.signald.util.KeyUtil;
import java.io.IOException;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asamk.signal.TrustLevel;
import org.asamk.signal.util.RandomUtils;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.KeyHelper;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.account.AccountAttributes;
import org.whispersystems.signalservice.api.account.PreKeyCollection;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Operations;
import org.whispersystems.signalservice.api.profiles.AvatarUploadParams;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.push.ServiceId.PNI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.CaptchaRequiredException;
import org.whispersystems.signalservice.internal.ServiceResponse;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.push.RegistrationSessionMetadataResponse;
import org.whispersystems.signalservice.internal.push.RequestVerificationCodeResponse;
import org.whispersystems.signalservice.internal.push.VerifyAccountResponse;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;

public class RegistrationManager {
  private final static Logger logger = LogManager.getLogger();
  private static final ConcurrentHashMap<String, RegistrationManager> registrationManagers = new ConcurrentHashMap<>();

  private final SignalServiceAccountManager accountManager;
  private final String e164;
  private final NumberVerification numberVerification;

  public static RegistrationManager get(String e164, UUID server) throws IOException, SQLException, ServerNotFoundException, InvalidProxyException {
    String key = e164 + server.toString();
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
    var server = Database.Get().ServersTable.getServer(serverUUID);
    SignalServiceConfiguration serviceConfiguration = server.getSignalServiceConfiguration();

    String password = Util.getSecret(18);
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.PASSWORD, password);

    DynamicCredentialsProvider credentialProvider = new DynamicCredentialsProvider(null, null, e164, password, SignalServiceAddress.DEFAULT_DEVICE_ID);
    GroupsV2Operations groupsV2Operations = GroupsUtil.GetGroupsV2Operations(serviceConfiguration);
    accountManager = new SignalServiceAccountManager(serviceConfiguration, credentialProvider, BuildConfig.USER_AGENT, groupsV2Operations, ServiceConfig.AUTOMATIC_NETWORK_RETRY);
    numberVerification = new NumberVerification(accountManager);
  }

  public RegistrationSessionMetadataResponse register(boolean voiceVerification, UUID server) throws IOException, InvalidInputException, SQLException {
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.LOCAL_REGISTRATION_ID, KeyHelper.generateRegistrationId(false));
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.LOCAL_PNI_REGISTRATION_ID, KeyHelper.generateRegistrationId(false));
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.ACI_IDENTITY_KEY_PAIR, KeyUtil.generateIdentityKeyPair().serialize());
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.PNI_IDENTITY_KEY_PAIR, KeyUtil.generateIdentityKeyPair().serialize());
    Database.Get().PendingAccountDataTable.set(e164, IPendingAccountDataTable.Key.SERVER_UUID, server.toString());

    return numberVerification.requestVerificationCode(voiceVerification);
  }

  public Manager verifyAccount(String verificationCode)
      throws IOException, InvalidInputException, SQLException, InvalidProxyException, InvalidKeyException, ServerNotFoundException, NoSuchAccountException {
    RegistrationSessionMetadataResponse verificationCodeResult = numberVerification.submitVerificationCode(verificationCode);

    int registrationID = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.LOCAL_REGISTRATION_ID);
    int pniRegistrationID = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.LOCAL_PNI_REGISTRATION_ID);
    ProfileKey profileKey = generateProfileKey();
    byte[] unidentifiedAccessKey = UnidentifiedAccess.deriveAccessKeyFrom(profileKey);

    AccountAttributes accountAttributes =
        new AccountAttributes(null, registrationID, false, false, true, null, unidentifiedAccessKey, false, false, ServiceConfig.CAPABILITIES, "", pniRegistrationID, null);

    IdentityKeyPair aciKeyPair = new IdentityKeyPair(Database.Get().PendingAccountDataTable.getBytes(e164, IPendingAccountDataTable.Key.ACI_IDENTITY_KEY_PAIR));
    int aciNextSignedPreKeyId = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.ACI_PRE_KEY_ID_OFFSET); // TODO: set this somehow
    SignedPreKeyRecord aciSignedPreKey = generateSignedPreKeyRecord(aciNextSignedPreKeyId, aciKeyPair.getPrivateKey());
    int aciNextKyberPreKeyOffset = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.ACI_NEXT_KYBER_PRE_KEY_OFFSET); // TODO: set this somehow
    KyberPreKeyRecord aciLastResortKyberPreKey = generateKyberPreKeyRecord(aciNextKyberPreKeyOffset, aciKeyPair.getPrivateKey());
    PreKeyCollection aciPreKeys = new PreKeyCollection(aciKeyPair.getPublicKey(), aciSignedPreKey, aciLastResortKyberPreKey);

    IdentityKeyPair pniKeyPair = new IdentityKeyPair(Database.Get().PendingAccountDataTable.getBytes(e164, IPendingAccountDataTable.Key.PNI_IDENTITY_KEY_PAIR));
    int pniNextSignedPreKeyId = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.PNI_PRE_KEY_ID_OFFSET); // TODO: set this somehow
    SignedPreKeyRecord pniSignedPreKey = generateSignedPreKeyRecord(pniNextSignedPreKeyId, pniKeyPair.getPrivateKey());
    int pniNextKyberPreKeyOffset = Database.Get().PendingAccountDataTable.getInt(e164, IPendingAccountDataTable.Key.PNI_NEXT_KYBER_PRE_KEY_OFFSET); // TODO: set this somehow
    KyberPreKeyRecord pniLastResortKyberPreKey = generateKyberPreKeyRecord(pniNextKyberPreKeyOffset, pniKeyPair.getPrivateKey());
    PreKeyCollection pniPreKeys = new PreKeyCollection(pniKeyPair.getPublicKey(), pniSignedPreKey, pniLastResortKyberPreKey);

    VerifyAccountResponse result = numberVerification.register(accountAttributes, aciPreKeys, pniPreKeys, true);

    ACI aci = ACI.from(UUID.fromString(result.getUuid()));
    PNI pni = PNI.from(UUID.fromString(result.getPni()));
    Account account = new Account(aci);

    String server = Database.Get().PendingAccountDataTable.getString(e164, IPendingAccountDataTable.Key.SERVER_UUID);
    Database.Get().AccountsTable.add(e164, aci, server == null ? null : UUID.fromString(server));
    account.setPNI(pni);

    Database.Get().AccountDataTable.set(aci, IAccountDataTable.Key.LAST_ACCOUNT_REPAIR, AccountRepair.getLatestVersion());

    String password = Database.Get().PendingAccountDataTable.getString(e164, IPendingAccountDataTable.Key.PASSWORD);
    account.setPassword(password);

    account.setACIIdentityKeyPair(aciKeyPair);

    account.setPNIIdentityKeyPair(pniKeyPair);

    account.getDB().IdentityKeysTable.saveIdentity(Database.Get(aci).RecipientsTable.get(aci), aciKeyPair.getPublicKey(), TrustLevel.TRUSTED_VERIFIED);

    account.setLocalRegistrationId(registrationID);
    account.setPniRegistrationId(pniRegistrationID);
    account.setDeviceId(SignalServiceAddress.DEFAULT_DEVICE_ID);

    Database.Get().PendingAccountDataTable.clear(e164);

    account.getDB().ProfileKeysTable.setProfileKey(account.getSelf(), profileKey);

    account.getSignalDependencies().getAccountManager().setVersionedProfile(aci, profileKey, "", "", "", Optional.empty(), AvatarUploadParams.unchanged(false), List.of());

    return Manager.get(aci);
  }

  public String getE164() { return e164; }

  public boolean hasPendingKeys() throws SQLException {
    return Database.Get().PendingAccountDataTable.getBytes(e164, IPendingAccountDataTable.Key.ACI_IDENTITY_KEY_PAIR) != null &&
        Database.Get().PendingAccountDataTable.getBytes(e164, IPendingAccountDataTable.Key.PNI_IDENTITY_KEY_PAIR) != null;
  }

  public boolean isRegistered() {
    try {
      Database.Get().AccountsTable.getACI(e164);
      return true;
    } catch (NoSuchAccountException e) {
      return false;
    } catch (SQLException e) {
      throw new AssertionError(e);
    }
  }

  private void handleResponseException(final ServiceResponse<?> response) throws IOException {
    final Optional<Throwable> throwableOptional = response.getExecutionError().or(response::getApplicationError);
    if (throwableOptional.isPresent()) {
      if (throwableOptional.get() instanceof IOException) {
        throw(IOException) throwableOptional.get();
      } else {
        throw new IOException(throwableOptional.get());
      }
    }
  }

  private ProfileKey generateProfileKey() throws InvalidInputException {
    byte[] key = new byte[32];
    RandomUtils.getSecureRandom().nextBytes(key);
    return new ProfileKey(key);
  }

  public static SignedPreKeyRecord generateSignedPreKeyRecord(final int signedPreKeyId, final ECPrivateKey privateKey) {
    var keyPair = Curve.generateKeyPair();
    byte[] signature;
    try {
      signature = Curve.calculateSignature(privateKey, keyPair.getPublicKey().serialize());
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  public static List<KyberPreKeyRecord> generateKyberPreKeyRecords(final int offset, final ECPrivateKey privateKey) {
    var records = new ArrayList<KyberPreKeyRecord>(ServiceConfig.PREKEY_BATCH_SIZE);
    for (var i = 0; i < ServiceConfig.PREKEY_BATCH_SIZE; i++) {
      var preKeyId = (offset + i) % ServiceConfig.PREKEY_MAXIMUM_ID;
      records.add(generateKyberPreKeyRecord(preKeyId, privateKey));
    }
    return records;
  }

  public static KyberPreKeyRecord generateKyberPreKeyRecord(final int preKeyId, final ECPrivateKey privateKey) {
    KEMKeyPair keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
    byte[] signature = privateKey.calculateSignature(keyPair.getPublicKey().serialize());

    return new KyberPreKeyRecord(preKeyId, System.currentTimeMillis(), keyPair, signature);
  }
}
