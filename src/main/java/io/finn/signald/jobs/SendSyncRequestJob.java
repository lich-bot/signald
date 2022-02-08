/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.jobs;

import io.finn.signald.Account;
import io.finn.signald.Manager;
import io.finn.signald.SignalDependencies;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.SignalSessionLock;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccessPair;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.multidevice.RequestMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SignalServiceSyncMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos;

public class SendSyncRequestJob implements Job {
  private final Account account;
  private final SignalServiceProtos.SyncMessage.Request.Type type;

  public SendSyncRequestJob(Account account, SignalServiceProtos.SyncMessage.Request.Type type) {
    this.account = account;
    this.type = type;
  }

  @Override
  public void run() throws NoSuchAccountException, SQLException, ServerNotFoundException, IOException, InvalidProxyException, UntrustedIdentityException, InvalidKeyException {
    SignalDependencies dependencies = account.getSignalDependencies();
    SignalServiceProtos.SyncMessage.Request request = SignalServiceProtos.SyncMessage.Request.newBuilder().setType(type).build();
    SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(request));
    SignalServiceMessageSender messageSender = dependencies.getMessageSender();
    Optional<UnidentifiedAccessPair> access = Manager.get(account.getACI()).getAccessPairFor(account.getSelf());
    try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
      messageSender.sendSyncMessage(message, access);
    } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
      account.getProtocolStore().handleUntrustedIdentityException(e);
      throw e;
    }
  }
}
