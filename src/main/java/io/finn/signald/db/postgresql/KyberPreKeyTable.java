/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.db.postgresql;

import io.finn.signald.Account;
import io.finn.signald.db.IKyberPreKeyStore;
import java.sql.SQLException;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.whispersystems.signalservice.api.push.ServiceId;

public class KyberPreKeyTable implements IKyberPreKeyStore {
  private final Account account;

  public KyberPreKeyTable(ServiceId.ACI aci) { account = new Account(aci); }

  @Override
  public void deleteAllStaleOneTimeKyberPreKeys(long l, int i) {
    throw new RuntimeException("not yet implemented");
  }

  @NotNull
  @Override
  public List<KyberPreKeyRecord> loadLastResortKyberPreKeys() {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void markAllOneTimeKyberPreKeysStaleIfNecessary(long l) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void removeKyberPreKey(int i) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void storeLastResortKyberPreKey(int i, @NotNull KyberPreKeyRecord kyberPreKeyRecord) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void deleteAccount(ServiceId.ACI aci) throws SQLException {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public KyberPreKeyRecord loadKyberPreKey(int i) throws InvalidKeyIdException {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public List<KyberPreKeyRecord> loadKyberPreKeys() {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void storeKyberPreKey(int i, KyberPreKeyRecord kyberPreKeyRecord) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public boolean containsKyberPreKey(int i) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public void markKyberPreKeyUsed(int i) {
    throw new RuntimeException("not yet implemented");
  }
}
