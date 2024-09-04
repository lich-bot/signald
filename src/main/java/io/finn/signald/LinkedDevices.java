/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import static org.whispersystems.signalservice.internal.util.Util.isEmpty;

import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import org.signal.core.util.Base64;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.kbs.MasterKey;

public class LinkedDevices {
  public static void add(Account account, URI uri) throws IOException, InvalidKeyException, NoSuchAccountException, SQLException, ServerNotFoundException, InvalidProxyException {
    Map<String, String> query = getQueryMap(uri.getRawQuery());
    String deviceIdentifier = query.get("uuid");
    String publicKeyEncoded = query.get("pub_key");

    if (isEmpty(deviceIdentifier) || isEmpty(publicKeyEncoded)) {
      throw new RuntimeException("Invalid device link uri");
    }

    SignalServiceAccountManager accountManager = account.getSignalDependencies().getAccountManager();

    ECPublicKey deviceKey = Curve.decodePoint(Base64.decode(publicKeyEncoded), 0);
    IdentityKeyPair aciKeyPair = account.getACIIdentityKeyPair();
    IdentityKeyPair pniKeyPair = account.getPNIIdentityKeyPair();
    ProfileKey profileKey = account.getDB().ProfileKeysTable.getProfileKey(account.getSelf());
    MasterKey masterKey = account.getOrCreateMasterKey();
    String verificationCode = accountManager.getNewDeviceVerificationCode();
    accountManager.addDevice(deviceIdentifier, deviceKey, aciKeyPair, pniKeyPair, profileKey, masterKey, verificationCode);
  }

  private static Map<String, String> getQueryMap(String query) {
    String[] params = query.split("&");
    Map<String, String> map = new HashMap<>();
    for (String param : params) {
      String name = URLDecoder.decode(param.split("=")[0], StandardCharsets.UTF_8);
      String value = URLDecoder.decode(param.split("=")[1], StandardCharsets.UTF_8);
      map.put(name, value);
    }
    return map;
  }
}
