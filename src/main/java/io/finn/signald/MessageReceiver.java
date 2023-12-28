/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import io.finn.signald.clientprotocol.MessageEncoder;
import io.finn.signald.db.*;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.jobs.BackgroundJobRunnerThread;
import io.finn.signald.jobs.ResetSessionJob;
import io.finn.signald.jobs.SendRetryMessageRequestJob;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.sentry.Sentry;
import java.io.IOException;
import java.net.Socket;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.metadata.*;
import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.protocol.*;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.whispersystems.signalservice.api.InvalidMessageStructureException;
import org.whispersystems.signalservice.api.SignalWebSocket;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipherResult;
import org.whispersystems.signalservice.api.messages.EnvelopeContentValidator;
import org.whispersystems.signalservice.api.messages.EnvelopeResponse;
import org.whispersystems.signalservice.api.messages.SignalServiceContent;
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.websocket.WebSocketConnectionState;
import org.whispersystems.signalservice.internal.push.Envelope;
import org.whispersystems.signalservice.internal.push.UnsupportedDataMessageException;

public class MessageReceiver implements Runnable {
  private final Account account;
  private final ECPublicKey unidentifiedSenderTrustRoot;
  private final IMessageQueueTable messageQueueTable;
  private int backoff = 0;
  private final SocketManager sockets;
  //  private final String uuid;
  private static final Logger logger = LogManager.getLogger();
  private static final HashMap<String, MessageReceiver> receivers = new HashMap<>();
  static final Gauge subscribedAccounts =
      Gauge.build().name(BuildConfig.NAME + "_subscribed_accounts").help("number of accounts subscribed to messages from the Signal server").register();
  static final Counter receivedMessagesCounter =
      Counter.build().name(BuildConfig.NAME + "_received_messages").help("number of messages received").labelNames("account_uuid", "error").register();

  private static final Histogram messageDecryptionTime =
      Histogram.build().name(BuildConfig.NAME + "_message_decryption_time").help("Time (in seconds) to decrypt incoming messages").labelNames("account_uuid").register();

  public MessageReceiver(ACI aci) throws SQLException, IOException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    var server = Database.Get().AccountsTable.getServer(aci);
    this.unidentifiedSenderTrustRoot = server.getUnidentifiedSenderRoot();
    this.account = new Account(aci);
    this.sockets = new SocketManager();
    this.messageQueueTable = account.getDB().MessageQueueTable;
  }

  public static void subscribe(ACI aci, MessageEncoder receiver)
      throws SQLException, IOException, NoSuchAccountException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    synchronized (receivers) {
      if (!receivers.containsKey(aci.toString())) {
        MessageReceiver r = new MessageReceiver(aci);
        receivers.put(aci.toString(), r);
        new Thread(r).start();
      }
      receivers.get(aci.toString()).sockets.add(receiver);
    }
    logger.debug("message receiver for " + Util.redact(aci) + " got new subscriber. subscriber count: " + receivers.get(aci.toString()).sockets.size());
  }

  public static boolean unsubscribe(ACI aci, Socket s) {
    synchronized (receivers) {
      if (!receivers.containsKey(aci.toString())) {
        return false;
      }
      return synchronizedUnsubscribe(aci, s);
    }
  }

  public static void unsubscribeAll(Socket s) {
    synchronized (receivers) {
      for (String r : receivers.keySet()) {
        synchronizedUnsubscribe(ACI.from(UUID.fromString(r)), s);
      }
    }
  }

  public static void unsubscribeAll(UUID account) {
    synchronized (receivers) {
      if (!receivers.containsKey(account.toString())) {
        return;
      }
      receivers.get(account.toString()).sockets.removeAll();
    }
  }

  public static void handleWebSocketConnectionStateChange(UUID accountUUID, WebSocketConnectionState connectionState, boolean unidentified) throws SQLException {
    synchronized (receivers) {
      MessageReceiver receiver = receivers.get(accountUUID.toString());
      if (receiver == null) {
        return;
      }

      receiver.sockets.broadcastWebSocketConnectionStateChange(connectionState, unidentified);

      switch (connectionState) {
      case AUTHENTICATION_FAILED:
        receivers.get(accountUUID.toString()).sockets.removeAll();
        break;
      case CONNECTED:
        receiver.sockets.broadcastListenStarted();
        if (receiver.backoff != 0) {
          receiver.backoff = 0;
          logger.debug("websocket connected, resetting backoff");
        }
        break;
      }
    }
  }

  public static void broadcastStorageStateChange(UUID accountUUID, long version) throws SQLException {
    synchronized (receivers) {
      MessageReceiver receiver = receivers.get(accountUUID.toString());
      if (receiver == null) {
        return;
      }
      receiver.sockets.broadcastStorageStateChange(version);
    }
  }

  // must be called from within a synchronized(receivers) block
  private static boolean synchronizedUnsubscribe(ACI aci, Socket s) {
    if (!receivers.containsKey(aci.toString())) {
      return false;
    }

    boolean removed = receivers.get(aci.toString()).remove(s);
    if (removed) {
      logger.debug("message receiver for " + Util.redact(aci) + " lost a subscriber. subscriber count: " + receivers.get(aci.toString()).sockets.size());
    }
    if (removed && receivers.get(aci.toString()).sockets.size() == 0) {
      logger.info("Last client for " + Util.redact(aci) + " unsubscribed, shutting down message pipe");
      try {
        SignalDependencies.get(aci).getWebSocket().disconnect();
      } catch (IOException | SQLException | ServerNotFoundException | InvalidProxyException | NoSuchAccountException e) {
        logger.catching(e);
      }
      receivers.remove(aci.toString());
    }
    return removed;
  }

  private boolean remove(Socket socket) { return sockets.remove(socket); }

  public void run() {
    boolean notifyOnConnect = true;
    Thread.currentThread().setName(Util.redact(account.getACI()) + "-receiver");
    logger.debug("starting message receiver for " + Util.redact(account.getACI()));
    try {
      while (sockets.size() > 0) {
        boolean ignoreAttachments = false;

        if (!Database.Get().AccountsTable.exists(account.getACI())) {
          logger.info("account no longer exists, not (re)-connecting");
          break;
        }

        try {
          subscribedAccounts.inc();
          if (notifyOnConnect) {
            this.sockets.broadcastListenStarted();
          } else {
            notifyOnConnect = true;
          }
          receiveMessages();
        } catch (IOException e) {
          if (sockets.size() == 0) {
            return;
          }
          logger.debug("disconnected from socket", e);
          if (backoff > 0) {
            this.sockets.broadcastListenStopped(e);
          }
        } catch (Throwable e) {
          this.sockets.broadcastListenStopped(e);
          logger.catching(e);
        } finally {
          subscribedAccounts.dec();
        }
        if (!account.exists()) {
          return; // exit the receive thread
        }
        if (backoff == 0) {
          notifyOnConnect = false;
          logger.debug("reconnecting immediately");
          backoff = 1;
        } else {
          if (backoff < 65) {
            backoff = backoff * 2;
          }
          logger.warn("Disconnected from socket, reconnecting in " + backoff + " seconds");
          TimeUnit.SECONDS.sleep(backoff);
        }
      }
      logger.debug("final subscriber disconnected, shutting down message receiver for " + Util.redact(account.getACI()));
    } catch (Exception e) {
      logger.error("shutting down message receiver for " + Util.redact(account.getACI()), e);
      Sentry.captureException(e);
      try {
        sockets.broadcastListenStopped(e);
      } catch (SQLException ex) {
        logger.error("SQL exception occurred stopping listener");
        Sentry.captureException(e);
      }
    }
  }

  private void receiveMessages() throws IOException, NoSuchAccountException, SQLException, ServerNotFoundException, InvalidProxyException {
    while (true) {
      logger.debug("processing cached messages");
      if (!processNextMessage()) {
        break;
      }
    }

    SignalWebSocket websocket = account.getSignalDependencies().getWebSocket();
    logger.debug("connecting to websocket");
    websocket.connect();

    try {
      while (true) {
        try {
          websocket.readMessageBatch(3600000, 1, envelopeResponses -> {
            logger.debug("received a batch of {} messages", envelopeResponses.size());
            for (EnvelopeResponse envelopeResponse : envelopeResponses) {
              SignalServiceEnvelope envelope = new SignalServiceEnvelope(envelopeResponse.getEnvelope(), envelopeResponse.getServerDeliveredTimestamp());
              try {
                messageQueueTable.storeEnvelope(envelope);
                websocket.sendAck(envelopeResponse);
              } catch (SQLException e) {
                logger.error("error storing incoming message:", e);
              } catch (IOException e) {
                logger.error("stored but failed to ack incoming message:", e);
              }
            }
          });
        } catch (TimeoutException e) {
          logger.info("websocket connection timed out");
          return;
        }
        processNextMessage();
      }
    } finally {
      logger.debug("disconnecting websocket");
      websocket.disconnect();
    }
  }

  private boolean processNextMessage() throws SQLException {
    StoredEnvelope storedEnvelope = messageQueueTable.nextEnvelope();
    if (storedEnvelope == null) {
      return false;
    }
    try {
      // TODO: signal-cli checks if storedEnvelope.envelope.isReceipt() and skips a lot of this if it is
      // https://github.com/AsamK/signal-cli/blob/375bdb79485ec90beb9a154112821a4657740b7a/lib/src/main/java/org/asamk/signal/manager/helper/IncomingMessageHandler.java#L101
      SignalServiceCipherResult cipherResult = decryptMessage(storedEnvelope.envelope);
      SignalServiceContent content = validate(storedEnvelope.envelope, cipherResult);
      this.sockets.broadcastIncomingMessage(storedEnvelope.envelope, content);
      receivedMessagesCounter.labels(this.account.getACI().toString(), "").inc();
    } catch (Exception e) {
      if (e.getCause() instanceof DuplicateMessageException) {
        logger.warn("ignoring DuplicateMessageException (see https://gitlab.com/signald/signald/-/issues/50)", e);
      } else if (e instanceof UntrustedIdentityException) {
        logger.debug("UntrustedIdentityException", e);
      } else if (e instanceof InvalidMetadataMessageException) {
        logger.warn("Received invalid metadata in incoming message", e);
      } else if (e instanceof ProtocolException || e.getCause() instanceof ProtocolException) {
        logger.warn("ProtocolException thrown while receiving", e);
      } else {
        logger.error("Unexpected error while receiving incoming message! Please report this at " + BuildConfig.ERROR_REPORTING_URL, e);
        Sentry.captureException(e);
      }
      this.sockets.broadcastReceiveFailure(storedEnvelope.envelope, e);
      String errorLabel = e.getClass().getCanonicalName();
      receivedMessagesCounter.labels(this.account.getACI().toString(), errorLabel).inc();
    }
    messageQueueTable.deleteEnvelope(storedEnvelope.databaseId);
    return true;
  }

  private SignalServiceCipherResult decryptMessage(SignalServiceEnvelope envelope)
      throws SQLException, NoSuchAccountException, ServerNotFoundException, IOException, InvalidProxyException, ProtocolInvalidKeyException, ProtocolInvalidMessageException,
             ProtocolUntrustedIdentityException, InvalidMetadataVersionException, ProtocolInvalidVersionException, InvalidMessageStructureException, ProtocolLegacyMessageException,
             InvalidMetadataMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, UntrustedIdentityException, InterruptedException {

    Semaphore sem = new Semaphore(1);
    int watchdogTime = Config.getDecryptionTimeout();
    if (watchdogTime > 0) {
      sem.acquire();
      Thread t = new Thread(() -> {
        // a watchdog thread that will make signald exit if decryption takes too long. This behavior is suboptimal, but
        // without this it just hangs and breaks in difficult to detect ways.
        try {
          boolean decryptFinished = sem.tryAcquire(watchdogTime, TimeUnit.SECONDS);
          if (!decryptFinished) {
            logger.error("took over {} seconds to decrypt, exiting", watchdogTime);
            System.exit(101);
          }
          sem.release();
        } catch (InterruptedException e) {
          logger.error("error in decryption watchdog thread", e);
          Sentry.captureException(e);
        }
      }, "DecryptWatchdogTimer");

      t.start();
    }

    CertificateValidator certificateValidator = new CertificateValidator(unidentifiedSenderTrustRoot);
    SignalServiceCipher cipher = new SignalServiceCipher(account.getSelf().getAddress(), account.getDeviceId(), account.getProtocolStore(),
                                                         account.getSignalDependencies().getSessionLock(), certificateValidator);
    Histogram.Timer timer = messageDecryptionTime.labels(account.getUUID().toString()).startTimer();
    try {
      return cipher.decrypt(envelope.getProto(), envelope.getServerDeliveredTimestamp());
    } catch (ProtocolUntrustedIdentityException e) {
      if (e.getCause() instanceof UntrustedIdentityException identityException) {
        account.getProtocolStore().saveIdentity(identityException.getName(), identityException.getUntrustedIdentity(), Config.getNewKeyTrustLevel());
        throw identityException;
      }
      throw e;
    } catch (SelfSendException e) {
      logger.debug("Dropping UD message from self (because that's what Signal Android does)");
      return null;
    } catch (ProtocolInvalidKeyIdException | ProtocolInvalidKeyException | ProtocolNoSessionException | ProtocolInvalidMessageException e) {
      logger.debug("Failed to decrypt incoming message: {}", e.getMessage());
      Database db = account.getDB();
      Recipient sender = db.RecipientsTable.get(e.getSender());
      boolean senderCapability = db.ProfileCapabilitiesTable.get(sender, IProfileCapabilitiesTable.SENDER_KEY);
      boolean selfCapability = db.ProfileCapabilitiesTable.get(account.getSelf(), IProfileCapabilitiesTable.SENDER_KEY);
      if (e.getSenderDevice() != account.getDeviceId() && senderCapability && selfCapability) {
        logger.info("incoming message could not be decrypted, asking sender to retry.");
        BackgroundJobRunnerThread.queue(new SendRetryMessageRequestJob(account, e, envelope));
      } else {
        logger.info("incoming message could not be decrypted, queuing session reset with sender");
        BackgroundJobRunnerThread.queue(new ResetSessionJob(account, sender));
      }
      throw e;
    } catch (ProtocolDuplicateMessageException e) {
      logger.debug("dropping duplicate message");
      return null;
    } finally {
      if (watchdogTime > 0) {
        sem.release();
      }
      double duration = timer.observeDuration();
      logger.debug("message decrypted in {} seconds", duration);
    }
  }

  private SignalServiceContent validate(SignalServiceEnvelope envelope, SignalServiceCipherResult cipherResult)
      throws ProtocolInvalidKeyException, ProtocolInvalidMessageException, UnsupportedDataMessageException, InvalidMessageStructureException, NoSuchAccountException, SQLException {
    final var content = cipherResult.getContent();
    final var envelopeMetadata = cipherResult.getMetadata();
    final var validationResult = EnvelopeContentValidator.INSTANCE.validate(envelope.getProto(), content);

    if (validationResult instanceof EnvelopeContentValidator.Result.Invalid v) {
      logger.warn("Invalid content! {}", v.getReason(), v.getThrowable());
      return null;
    }

    if (validationResult instanceof EnvelopeContentValidator.Result.UnsupportedDataMessage v) {
      logger.warn("Unsupported DataMessage! Our version: {}, their version: {}", v.getOurVersion(), v.getTheirVersion());
      return null;
    }

    return SignalServiceContent.Companion.createFrom(account.getE164(), envelope.getProto(), envelopeMetadata, content, envelope.getServerDeliveredTimestamp());
  }

  static class SocketManager {
    private final List<MessageEncoder> listeners = Collections.synchronizedList(new ArrayList<>());

    public synchronized void add(MessageEncoder b) {
      synchronized (listeners) {
        Iterator<MessageEncoder> i = listeners.iterator();
        while (i.hasNext()) {
          MessageEncoder r = i.next();
          if (r.equals(b)) {
            logger.debug("ignoring duplicate subscribe request");
            return;
          }
        }
        listeners.add(b);
      }
    }

    public synchronized boolean remove(Socket b) {
      synchronized (listeners) {
        Iterator<MessageEncoder> i = listeners.iterator();
        while (i.hasNext()) {
          MessageEncoder r = i.next();
          if (r.equals(b)) {
            return listeners.remove(r);
          }
        }
      }
      return false;
    }

    public synchronized void removeAll() {
      synchronized (listeners) { listeners.removeAll(listeners); }
    }

    public synchronized int size() { return listeners.size(); }

    private void broadcast(broadcastMessage b) throws SQLException {
      synchronized (listeners) {
        for (MessageEncoder l : this.listeners) {
          if (l.isClosed()) {
            listeners.remove(l);
            continue;
          }
          try {
            b.broadcast(l);
          } catch (IOException e) {
            logger.warn("IOException while writing to client socket: " + e.getMessage());
          }
        }
      }
    }

    public void broadcastWebSocketConnectionStateChange(WebSocketConnectionState state, boolean unidentified) throws SQLException {
      broadcast(r -> r.broadcastWebSocketConnectionStateChange(state, unidentified));
    }

    public void broadcastIncomingMessage(SignalServiceEnvelope envelope, SignalServiceContent content) throws SQLException {
      broadcast(r -> r.broadcastIncomingMessage(envelope, content));
    }

    public void broadcastReceiveFailure(SignalServiceEnvelope envelope, Throwable exception) throws SQLException { broadcast(r -> r.broadcastReceiveFailure(envelope, exception)); }

    public void broadcastListenStarted() throws SQLException { broadcast(MessageEncoder::broadcastListenStarted); }

    public void broadcastListenStopped(Throwable exception) throws SQLException { broadcast(r -> r.broadcastListenStopped(exception)); }

    public void broadcastStorageStateChange(long version) throws SQLException { broadcast(r -> r.broadcastStorageChange(version)); }

    private interface broadcastMessage {
      void broadcast(MessageEncoder r) throws IOException, SQLException;
    }
  }
}
