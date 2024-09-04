/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.util;

import static io.finn.signald.ServiceConfig.PREKEY_MAXIMUM_ID;

import io.finn.signald.ServiceConfig;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.asamk.signal.util.RandomUtils;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.signalservice.api.push.ServiceIdType;

public class KeyUtil {
  private static final SecureRandom secureRandom = new SecureRandom();

  public static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair djbKeyPair = Curve.generateKeyPair();
    IdentityKey djbIdentityKey = new IdentityKey(djbKeyPair.getPublicKey());
    ECPrivateKey djbPrivateKey = djbKeyPair.getPrivateKey();

    return new IdentityKeyPair(djbIdentityKey, djbPrivateKey);
  }

  public static int getRandomInt(int bound) { return secureRandom.nextInt(bound); }

  public static ProfileKey generateProfileKey() throws InvalidInputException {
    byte[] key = new byte[32];
    secureRandom.nextBytes(key);
    return new ProfileKey(key);
  }
  public static KyberPreKeyRecord generateKyberPreKeyRecord(final int preKeyId, final ECPrivateKey privateKey) {
    KEMKeyPair keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
    byte[] signature = privateKey.calculateSignature(keyPair.getPublicKey().serialize());

    return new KyberPreKeyRecord(preKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  public static List<KyberPreKeyRecord> generateKyberPreKeyRecords(final int offset, final ECPrivateKey privateKey) {
    var records = new ArrayList<KyberPreKeyRecord>(ServiceConfig.PREKEY_BATCH_SIZE);
    for (var i = 0; i < ServiceConfig.PREKEY_BATCH_SIZE; i++) {
      var preKeyId = (offset + i) % PREKEY_MAXIMUM_ID;
      records.add(generateKyberPreKeyRecord(preKeyId, privateKey));
    }
    return records;
  }
}
