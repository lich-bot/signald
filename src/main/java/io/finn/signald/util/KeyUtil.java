/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.util;

import static io.finn.signald.ServiceConfig.PREKEY_MAXIMUM_ID;

import java.security.SecureRandom;
import org.asamk.signal.util.RandomUtils;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;

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
}
