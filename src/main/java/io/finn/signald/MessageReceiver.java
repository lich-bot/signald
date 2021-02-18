/*
 * Copyright (C) 2020 Finn Herzfeld
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

import io.finn.signald.clientprotocol.v1.JsonMessageEnvelope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.SelfSendException;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.*;

import java.io.IOException;
import java.net.Socket;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;

class MessageReceiver implements Manager.ReceiveMessageHandler, Runnable {
  final String username;
  private SocketManager sockets;
  private static final Logger logger = LogManager.getLogger();

  public MessageReceiver(String username) {
    this.username = username;
    this.sockets = new SocketManager();
  }

  public void subscribe(Socket s) { this.sockets.add(s); }

  public boolean unsubscribe(Socket s) {
    boolean removed = sockets.remove(s);
    if (removed && sockets.size() == 0) {
      logger.info("Last client for " + Util.redact(this.username) + " unsubscribed, shutting down message pipe!");
      try {
        Manager.get(username).shutdownMessagePipe();
      } catch (IOException | NoSuchAccountException | SQLException e) {
        logger.catching(e);
      }
    }
    return removed;
  }

  public void run() {
    try {
      Thread.currentThread().setName(Util.redact(username) + "-receiver");
      Manager manager = Manager.get(username);
      while (sockets.size() > 0) {
        double timeout = 3600;
        boolean returnOnTimeout = true;
        boolean ignoreAttachments = false;
        try {
          this.sockets.broadcast(new JsonMessageWrapper("listen_started", username, (String)null));
          manager.receiveMessages((long)(timeout * 1000), TimeUnit.MILLISECONDS, returnOnTimeout, ignoreAttachments, this);
          this.sockets.broadcast(new JsonMessageWrapper("listen_stopped", username, (String)null));
        } catch (IOException e) {
          this.sockets.broadcast(new JsonMessageWrapper("listen_stopped", username, e));
          if (sockets.size() > 0) {
            throw e;
          }
        } catch (AssertionError e) {
          this.sockets.broadcast(new JsonMessageWrapper("listen_stopped", username, e));
          logger.catching(e);
        }
      }
    } catch (Exception e) {
      logger.catching(e);
    }
  }

  @Override
  public void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, Throwable exception) {
    String type = "message";
    if (exception != null) {
      if (exception instanceof SelfSendException) {
        logger.debug("ignoring SelfSendException (see https://gitlab.com/signald/signald/-/issues/24)");
      } else if (exception instanceof DuplicateMessageException || exception.getCause() instanceof DuplicateMessageException) {
        logger.warn("ignoring DuplicateMessageException (see https://gitlab.com/signald/signald/-/issues/50): " + exception.toString());
      } else if (exception instanceof UntrustedIdentityException) {
        logger.debug("UntrustedIdentityException", exception.toString());
      } else if (exception instanceof InvalidMetadataMessageException) {
        logger.warn("Received invalid metadata in incoming message: " + exception.toString());
      } else {
        logger.error("Unexpected error while receiving incoming message! Please report this at " + BuildConfig.ERROR_REPORTING_URL, exception);
      }
      type = "unreadable_message";
    }

    try {
      if (exception instanceof org.whispersystems.libsignal.UntrustedIdentityException) {
        JsonUntrustedIdentityException message = new JsonUntrustedIdentityException((org.whispersystems.libsignal.UntrustedIdentityException)exception, username);
        this.sockets.broadcast(new JsonMessageWrapper("inbound_identity_failure", message, (Throwable)null));
      }
      if (envelope != null) {
        JsonMessageEnvelope message = new JsonMessageEnvelope(envelope, content, username);
        if (shouldBroadcast(content)) {
          this.sockets.broadcast(new JsonMessageWrapper(type, message, exception));
        }
      } else {
        this.sockets.broadcast(new JsonMessageWrapper(type, null, exception));
      }
    } catch (IOException | NoSuchAccountException | SQLException e) {
      logger.catching(e);
    }
  }

  private boolean shouldBroadcast(SignalServiceContent content) {
    if (content == null) {
      return true;
    }
    if (content.getDataMessage().isPresent()) {
      SignalServiceDataMessage dataMessage = content.getDataMessage().get();
      if (dataMessage.getGroupContext().isPresent()) {
        SignalServiceGroupContext group = dataMessage.getGroupContext().get();
        if (group.getGroupV1Type() == SignalServiceGroup.Type.REQUEST_INFO) {
          return false;
        }
      }
    }
    return true;
  }
}
