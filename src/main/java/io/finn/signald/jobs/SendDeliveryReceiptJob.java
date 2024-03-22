/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.jobs;

import io.finn.signald.Account;
import io.finn.signald.Manager;
import io.finn.signald.MessageSender;
import io.finn.signald.clientprotocol.v1.Server;
import io.finn.signald.db.Recipient;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.whispersystems.signalservice.api.messages.SignalServiceReceiptMessage;
import org.whispersystems.signalservice.api.push.exceptions.ProofRequiredException;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;

public class SendDeliveryReceiptJob implements Job {
  private static final Logger logger = LogManager.getLogger();

  private final Account account;
  private final Recipient recipient;
  private final List<Long> timestamps = new ArrayList<>();

  public SendDeliveryReceiptJob(Account account, Recipient recipient, Long timestamp) {
    this.account = account;
    this.recipient = recipient;
  }

  @Override
  public void run() throws IOException, SQLException {
    SignalServiceReceiptMessage message = new SignalServiceReceiptMessage(SignalServiceReceiptMessage.Type.DELIVERY, timestamps, System.currentTimeMillis());
    try {
      new MessageSender(account).sendReceipt(message, recipient);
    } catch (UnregisteredUserException e) {
      logger.debug("tried to send a receipt to an unregistered user {}", recipient.toRedactedString());
    } catch (ProofRequiredException e) {
      logger.warn("ProofRequiredException while sending delivery receipt job to {}", recipient.toRedactedString());
    } catch (NoSuchAccountException | ServerNotFoundException | InvalidProxyException e) {
      logger.error("unexpected error sending delivery receipt: ", e);
    }
  }
}
