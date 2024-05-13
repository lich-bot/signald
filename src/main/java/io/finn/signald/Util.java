/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import org.signal.core.util.Base64;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public class Util {
  public static String getSecret(int size) {
    byte[] secret = getSecretBytes(size);
    return Base64.encodeWithPadding(secret);
  }

  public static byte[] getSecretBytes(int size) {
    byte[] secret = new byte[size];
    getSecureRandom().nextBytes(secret);
    return secret;
  }

  private static SecureRandom getSecureRandom() {
    try {
      return SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public static String redact(SignalProtocolAddress address) { return redact(address.getName()) + "." + address.getDeviceId(); }

  public static String redact(SignalServiceAddress address) { return redact(address.getServiceId()); }

  public static String redact(ServiceId serviceId) {
    String prefix = "";
    if (serviceId instanceof ServiceId.ACI) {
      prefix = "ACI:";
    } else if (serviceId instanceof ServiceId.PNI) {
      prefix = "PNI:";
    }
    return prefix + redact(serviceId.getRawUuid().toString());
  }

  public static String redact(UUID uuid) { return redact(uuid.toString()); }

  public static String redact(String in) {
    if (in == null) {
      return "[null]";
    }

    int plaintextSize = 3;
    int redactedSize = in.length() <= plaintextSize ? in.length() : in.length() - plaintextSize;

    return String.format("[redacted %s]", redactedSize) + in.substring(redactedSize);
  }

  public static void copyStream(InputStream input, OutputStream output, int bufferSize) throws IOException {
    byte[] buffer = new byte[bufferSize];
    int read;

    while ((read = input.read(buffer)) != -1) {
      output.write(buffer, 0, read);
    }
  }

  public static byte[] readFully(InputStream in) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Util.copyStream(in, baos);
    return baos.toByteArray();
  }

  public static void copyStream(InputStream input, OutputStream output) throws IOException { copyStream(input, output, 4096); }
}
