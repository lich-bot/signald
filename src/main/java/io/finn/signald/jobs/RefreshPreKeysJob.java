/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.jobs;

import io.finn.signald.Account;
import io.finn.signald.ServiceConfig;
import io.finn.signald.db.DatabaseAccountDataStore;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.util.KeyUtil;
import java.io.IOException;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.Medium;
import org.whispersystems.signalservice.api.account.PreKeyUpload;
import org.whispersystems.signalservice.api.push.ServiceIdType;
import org.whispersystems.signalservice.internal.push.OneTimePreKeyCounts;

public class RefreshPreKeysJob implements Job {
  public static long INTERVAL = TimeUnit.DAYS.toMillis(3);
  private static final Logger logger = LogManager.getLogger();

  private final Account account;

  public RefreshPreKeysJob(Account account) { this.account = account; }

  @Override
  public void run() throws SQLException, NoSuchAccountException, ServerNotFoundException, IOException, InvalidProxyException, InvalidKeyException {
    long lastRefresh = account.getLastPreKeyRefresh();
    if (lastRefresh <= 0) {
      logger.info("generating pre keys");
      refreshPreKeys(ServiceIdType.ACI, true);
      refreshPreKeys(ServiceIdType.PNI, true);
    } else {
      refreshPreKeys(ServiceIdType.ACI, false);
      refreshPreKeys(ServiceIdType.PNI, false);
    }
    account.setLastPreKeyRefreshNow();
  }

  public static void runIfNeeded(Account account) throws SQLException, IOException, InvalidKeyException, NoSuchAccountException, ServerNotFoundException, InvalidProxyException {
    long lastRefresh = account.getLastPreKeyRefresh();
    if (System.currentTimeMillis() - lastRefresh > INTERVAL) {
      RefreshPreKeysJob job = new RefreshPreKeysJob(account);
      job.run();
    }
  }

  private void refreshPreKeys(ServiceIdType serviceIdType, boolean force)
      throws IOException, SQLException, InvalidKeyException, NoSuchAccountException, ServerNotFoundException, InvalidProxyException {
    if (serviceIdType != ServiceIdType.ACI) {
      // TODO
      return;
    }

    IdentityKeyPair identityKeyPair = serviceIdType == ServiceIdType.ACI ? account.getACIIdentityKeyPair() : account.getPNIIdentityKeyPair();
    OneTimePreKeyCounts counts = account.getSignalDependencies().getAccountManager().getPreKeyCounts(serviceIdType);

    List<PreKeyRecord> oneTimePreKeys = null;
    if (force || counts.getEcCount() < ServiceConfig.PREKEY_MINIMUM_COUNT) {
      oneTimePreKeys = generatePreKeys();
    }

    SignedPreKeyRecord signedPreKeyRecord = null;
    if (force || signedPreKeyNeedsRefresh(serviceIdType)) {
      signedPreKeyRecord = generateSignedPreKey(identityKeyPair);
    }

    List<KyberPreKeyRecord> kyberPreKeyRecords = null;
    if (force || counts.getKyberCount() < ServiceConfig.PREKEY_MINIMUM_COUNT) {
      kyberPreKeyRecords = generateKyberPreKeys(serviceIdType, identityKeyPair);
    }

    KyberPreKeyRecord lastResortKyberPreKeyRecord = null;
    if (force || lastResortKyberPreKeyNeedsRefresh(serviceIdType)) {
      lastResortKyberPreKeyRecord = generateLastResortKyberPreKey(serviceIdType, identityKeyPair, kyberPreKeyRecords == null ? 0 : kyberPreKeyRecords.size());
    }

    PreKeyUpload p = new PreKeyUpload(serviceIdType, identityKeyPair.getPublicKey(), signedPreKeyRecord, oneTimePreKeys, lastResortKyberPreKeyRecord, kyberPreKeyRecords);
    account.getSignalDependencies().getAccountManager().setPreKeys(p);

    try {
      if (kyberPreKeyRecords != null) {
        account.addKyberPreKeys(serviceIdType, kyberPreKeyRecords);
      }
      if (lastResortKyberPreKeyRecord != null) {
        account.addLastResortKyberPreKey(serviceIdType, lastResortKyberPreKeyRecord);
      }
    } catch (Exception e) {
      logger.error("error storing generated kyber keys: {}", e);
    }
  }

  private List<PreKeyRecord> generatePreKeys() throws SQLException {
    List<PreKeyRecord> records = new LinkedList<>();

    DatabaseAccountDataStore protocolStore = account.getProtocolStore();
    for (int i = 0; i < ServiceConfig.PREKEY_BATCH_SIZE; i++) {
      int preKeyId = (account.getPreKeyIdOffset() + i) % Medium.MAX_VALUE;
      ECKeyPair keyPair = Curve.generateKeyPair();
      PreKeyRecord record = new PreKeyRecord(preKeyId, keyPair);

      protocolStore.storePreKey(preKeyId, record);
      records.add(record);
    }

    account.setPreKeyIdOffset((account.getPreKeyIdOffset() + ServiceConfig.PREKEY_BATCH_SIZE + 1) % Medium.MAX_VALUE);

    return records;
  }

  private SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKey) throws SQLException, InvalidKeyException {
    ECKeyPair keyPair = Curve.generateKeyPair();
    byte[] signature = Curve.calculateSignature(identityKey.getPrivateKey(), keyPair.getPublicKey().serialize());
    int signedPreKeyId = account.getNextSignedPreKeyId(ServiceIdType.ACI);
    SignedPreKeyRecord record = new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
    account.getProtocolStore().storeSignedPreKey(signedPreKeyId, record);
    account.setActiveSignedPreKeyId(ServiceIdType.ACI, signedPreKeyId);
    account.setAciNextSignedPreKeyId((signedPreKeyId + 1) % Medium.MAX_VALUE);
    return record;
  }

  public List<KyberPreKeyRecord> generateKyberPreKeys(ServiceIdType serviceIdType, final IdentityKeyPair identityKeyPair) throws SQLException {
    int offset = account.getNextKyberPreKeyId(serviceIdType);
    return KeyUtil.generateKyberPreKeyRecords(offset, identityKeyPair.getPrivateKey());
  }

  private boolean signedPreKeyNeedsRefresh(ServiceIdType serviceIdType) throws SQLException {
    int activeSignedPreKeyId = account.getActiveSignedPreKeyId(serviceIdType);
    if (activeSignedPreKeyId == -1) {
      return true;
    }

    try {
      SignedPreKeyRecord signedPreKeyRecord = account.getProtocolStore().loadSignedPreKey(activeSignedPreKeyId);
      return signedPreKeyRecord.getTimestamp() < System.currentTimeMillis() - ServiceConfig.SIGNED_PREKEY_ROTATE_AGE;
    } catch (InvalidKeyIdException e) {
      return true;
    }
  }

  private boolean lastResortKyberPreKeyNeedsRefresh(ServiceIdType serviceIdType) throws SQLException {
    int activeLastResortKyberPreKeyId = account.getActiveLastResortKyberPreKeyId(serviceIdType);
    if (activeLastResortKyberPreKeyId == -1) {
      return true;
    }
    try {
      KyberPreKeyRecord kyberPreKeyRecord = account.getProtocolStore().loadKyberPreKey(activeLastResortKyberPreKeyId);
      return kyberPreKeyRecord.getTimestamp() < System.currentTimeMillis() - ServiceConfig.SIGNED_PREKEY_ROTATE_AGE;
    } catch (InvalidKeyIdException e) {
      return true;
    }
  }

  private KyberPreKeyRecord generateLastResortKyberPreKey(ServiceIdType serviceIdType, IdentityKeyPair identityKeyPair, final int offset) throws SQLException {
    int signedPreKeyId = account.getNextKyberPreKeyId(serviceIdType) + offset;
    return KeyUtil.generateKyberPreKeyRecord(signedPreKeyId, identityKeyPair.getPrivateKey());
  }
}
