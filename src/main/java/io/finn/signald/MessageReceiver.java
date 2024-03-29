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
import io.finn.signald.jobs.*;
import io.finn.signald.util.FileUtil;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.sentry.Sentry;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asamk.signal.TrustLevel;
import org.signal.libsignal.metadata.*;
import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.protocol.*;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.groups.GroupSessionBuilder;
import org.signal.libsignal.protocol.message.DecryptionErrorMessage;
import org.signal.libsignal.protocol.message.SenderKeyDistributionMessage;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.signalservice.api.InvalidMessageStructureException;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalWebSocket;
import org.whispersystems.signalservice.api.crypto.SignalGroupSessionBuilder;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipherResult;
import org.whispersystems.signalservice.api.groupsv2.InvalidGroupStateException;
import org.whispersystems.signalservice.api.messages.*;
import org.whispersystems.signalservice.api.messages.multidevice.*;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.MissingConfigurationException;
import org.whispersystems.signalservice.api.storage.StorageKey;
import org.whispersystems.signalservice.api.websocket.WebSocketConnectionState;
import org.whispersystems.signalservice.internal.push.SyncMessage;
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
    SignalWebSocket websocket = account.getSignalDependencies().getWebSocket();
    logger.debug("connecting to websocket");
    websocket.connect();

    try {
      while (true) {
        for (StoredEnvelope storedEnvelope = messageQueueTable.nextEnvelope(); storedEnvelope != null; storedEnvelope = messageQueueTable.nextEnvelope()) {
          processNextMessage(storedEnvelope);
        }
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
      }
    } finally {
      logger.debug("disconnecting websocket");
      websocket.disconnect();
    }
  }

  private void processNextMessage(StoredEnvelope storedEnvelope) throws SQLException {
    if (storedEnvelope.envelope.isReceipt()) {
      // wat do?
      return;
    }

    try {
      // TODO: signal-cli checks if storedEnvelope.envelope.isReceipt() and skips a lot of this if it is
      // https://github.com/AsamK/signal-cli/blob/375bdb79485ec90beb9a154112821a4657740b7a/lib/src/main/java/org/asamk/signal/manager/helper/IncomingMessageHandler.java#L101
      SignalServiceCipherResult cipherResult = decryptMessage(storedEnvelope.envelope);
      SignalServiceContent content = validate(storedEnvelope.envelope, cipherResult);
      handleIncomingMessage(storedEnvelope.envelope, content);
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

  private void handleIncomingMessage(SignalServiceEnvelope envelope, SignalServiceContent content)
      throws SQLException, IOException, NoSuchAccountException, ServerNotFoundException, InvalidProxyException, InvalidInputException, MissingConfigurationException,
             VerificationFailedException, InvalidMessageException {
    Database db = account.getDB();
    SignalDependencies signalDependencies = account.getSignalDependencies();

    SignalServiceAddress sourceSignalServiceAddress;
    if (envelope.getSourceServiceId().isPresent()) {
      sourceSignalServiceAddress = new SignalServiceAddress(ServiceId.parseOrNull(envelope.getSourceServiceId().get()));
    } else {
      sourceSignalServiceAddress = content.getSender();
    }
    Recipient source = db.RecipientsTable.get(sourceSignalServiceAddress);
    int sourceDeviceId = envelope.isUnidentifiedSender() ? envelope.getSourceDevice() : content.getSenderDevice();

    if (content.getDataMessage().isPresent()) {
      if (content.isNeedsReceipt()) {
        BackgroundJobRunnerThread.queue(new SendDeliveryReceiptJob(account, source, content.getTimestamp()));
      }
      SignalServiceDataMessage message = content.getDataMessage().get();
      handleSignalServiceDataMessage(message, false, source, account.getSelf());
    }

    if (content.getDecryptionErrorMessage().isPresent()) {
      DecryptionErrorMessage message = content.getDecryptionErrorMessage().get();
      logger.debug("Received a decryption error message (resend request for {})", message.getTimestamp());
      if (message.getRatchetKey().isPresent()) {
        if (message.getDeviceId() == account.getDeviceId() && account.getProtocolStore().isCurrentRatchetKey(source, sourceDeviceId, message.getRatchetKey().get())) {
          logger.debug("Resetting the session with sender");
          BackgroundJobRunnerThread.queue(new ResetSessionJob(account, source));
        }
      } else {
        logger.debug("Reset shared sender keys with this recipient");
        db.SenderKeySharedTable.deleteSharedWith(source);
      }
    }

    if (content.getEditMessage().isPresent()) {
      // TODO
    }

    if (content.getPniSignatureMessage().isPresent()) {
      // TODO
    }

    if (content.getReceiptMessage().isPresent()) {
      // TODO
    }

    if (content.getSenderKeyDistributionMessage().isPresent()) {
      logger.debug("handling sender key distribution message from {}", Util.redact(content.getSender().getIdentifier()));
      SenderKeyDistributionMessage message = content.getSenderKeyDistributionMessage().get();
      SignalProtocolAddress protocolAddress = sourceSignalServiceAddress.getServiceId().toProtocolAddress(sourceDeviceId);
      new SignalGroupSessionBuilder(signalDependencies.getSessionLock(), new GroupSessionBuilder(account.getProtocolStore())).process(protocolAddress, message);
    }

    if (content.getStoryMessage().isPresent()) {
      // TODO: download any story attachments
      SignalServiceStoryMessage story = content.getStoryMessage().get();
      if (story.getFileAttachment().isPresent()) {
        retrieveAttachment(story.getFileAttachment().get());
      }
    }

    if (content.getSyncMessage().isPresent()) {
      handleSyncMessage(content);
    }

    if (envelope.isPreKeySignalMessage()) {
      BackgroundJobRunnerThread.queue(new RefreshPreKeysJob(account));
    }
  }

  private void handleSignalServiceDataMessage(SignalServiceDataMessage message, boolean isSync, Recipient source, Recipient destination)
      throws MissingConfigurationException, IOException, VerificationFailedException, SQLException, InvalidInputException {

    if (message.getGroupContext().isPresent()) {
      SignalServiceGroupContext groupContext = message.getGroupContext().get();
      if (groupContext.getGroupV2().isPresent()) {
        SignalServiceGroupV2 group = message.getGroupContext().get().getGroupV2().get();
        var localState = Database.Get(account.getACI()).GroupsTable.get(group);

        if (localState.isEmpty() || localState.get().getRevision() < group.getRevision()) {
          try {
            account.getGroups().getGroup(group);
          } catch (InvalidGroupStateException | InvalidProxyException | NoSuchAccountException | ServerNotFoundException e) {
            logger.warn("error fetching state of incoming group", e);
          }
        }
      }
    } else {
      account.getDB().ContactsTable.update(isSync ? destination : source, null, null, null, message.getExpiresInSeconds(), null);
    }

    if (message.isEndSession()) {
      handleEndSession(isSync ? destination : source);
    }

    if (message.getAttachments().isPresent()) {
      for (SignalServiceAttachment attachment : message.getAttachments().get()) {
        try {
          retrieveAttachment(attachment);
        } catch (IOException | InvalidMessageException | NoSuchAccountException | ServerNotFoundException | InvalidProxyException e) {
          String id = attachment.isPointer() ? attachment.asPointer().getRemoteId().toString() : "";
          logger.warn("Failed to retrieve attachment ({}): {}", id, e.getMessage());
        }
      }
    }

    if (message.getPreviews().isPresent()) {
      for (SignalServicePreview preview : message.getPreviews().get()) {
        if (preview.getImage().isPresent()) {
          SignalServiceAttachment attachment = preview.getImage().get();
          try {
            retrieveAttachment(attachment);
          } catch (IOException | InvalidMessageException | NoSuchAccountException | ServerNotFoundException | InvalidProxyException e) {
            String id = attachment.isPointer() ? attachment.asPointer().getRemoteId().toString() : "";
            logger.warn("Failed to retrieve preview attachment ({}): {}", id, e);
          }
        }
      }
    }

    if (message.getProfileKey().isPresent() && message.getProfileKey().get().length == 32) {
      final ProfileKey profileKey;
      try {
        profileKey = new ProfileKey(message.getProfileKey().get());
      } catch (InvalidInputException e) {
        throw new AssertionError(e);
      }
      account.getDB().ProfileKeysTable.setProfileKey(source, profileKey);
      RefreshProfileJob.queueIfNeeded(account, source);
    }

    if (message.getSticker().isPresent()) {
      DownloadStickerJob job = new DownloadStickerJob(account.getACI(), message.getSticker().get());
      if (job.needsDownload()) {
        try {
          job.run();
        } catch (NoSuchAccountException | InvalidMessageException | ServerNotFoundException | InvalidKeyException | InvalidProxyException e) {
          logger.error("Sticker failed to download");
          Sentry.captureException(e);
        }
      }
    }

    if (message.getSharedContacts().isPresent()) {
      for (var contact : message.getSharedContacts().get()) {
        if (contact.getAvatar().isPresent()) {
          try {
            retrieveAttachment(contact.getAvatar().get().getAttachment());
          } catch (InvalidMessageException | NoSuchAccountException | ServerNotFoundException | InvalidProxyException e) {
            logger.error("error downloading profile picture for shared account: ", e);
          }
        }
      }
    }
  }

  private void handleSyncMessage(SignalServiceContent content) throws SQLException, IOException, InvalidInputException, MissingConfigurationException, VerificationFailedException {
    if (content.getSyncMessage().isEmpty()) {
      return;
    }

    SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();
    Database db = account.getDB();

    account.setMultiDevice(true);
    if (syncMessage.getSent().isPresent()) {
      SentTranscriptMessage sentTranscriptMessage = syncMessage.getSent().get();
      if (sentTranscriptMessage.getDataMessage().isPresent()) {
        SignalServiceDataMessage message = sentTranscriptMessage.getDataMessage().get();

        Recipient sendMessageRecipient = null;
        if (syncMessage.getSent().get().getDestination().isPresent()) {
          sendMessageRecipient = db.RecipientsTable.get(syncMessage.getSent().get().getDestination().get());
        }

        handleSignalServiceDataMessage(message, true, account.getSelf(), sendMessageRecipient);
      }
    }

    if (syncMessage.getRequest().isPresent() && account.getDeviceId() == SignalServiceAddress.DEFAULT_DEVICE_ID) {
      RequestMessage rm = syncMessage.getRequest().get();
      if (rm.isContactsRequest()) {
        BackgroundJobRunnerThread.queue(new SendContactsSyncJob(account));
      }
      logger.info("received contact sync request from device " + content.getSenderDevice());
    }

    if (syncMessage.getBlockedList().isPresent()) {
      // TODO store list of blocked numbers
      logger.info("received list of blocked users from device " + content.getSenderDevice());
    }

    if (syncMessage.getContacts().isPresent()) {
      File tmpFile = null;
      try {
        tmpFile = FileUtil.createTempFile();
        final ContactsMessage contactsMessage = syncMessage.getContacts().get();
        try (InputStream attachmentAsStream = retrieveAttachmentAsStream(contactsMessage.getContactsStream().asPointer(), tmpFile)) {
          DeviceContactsInputStream s = new DeviceContactsInputStream(attachmentAsStream);
          DeviceContact c;
          while ((c = s.read()) != null) {
            Recipient recipient = db.RecipientsTable.get(c.getAddress());
            db.ContactsTable.update(c);
            if (c.getAvatar().isPresent()) {
              retrieveAttachment((SignalServiceAttachment)c.getAvatar().get(), FileUtil.getContactAvatarFile(recipient));
            }
            if (c.getProfileKey().isPresent()) {
              db.ProfileKeysTable.setProfileKey(recipient, c.getProfileKey().get());
            }
          }
        }
        logger.info("received contacts from device " + content.getSenderDevice());
      } catch (Exception e) {
        logger.catching(e);
      } finally {
        if (tmpFile != null) {
          try {
            Files.delete(tmpFile.toPath());
          } catch (IOException e) {
            logger.warn("Failed to delete received contacts temp file \"" + tmpFile + "\": " + e.getMessage());
          }
        }
      }
    }

    if (syncMessage.getVerified().isPresent()) {
      VerifiedMessage verifiedMessage = syncMessage.getVerified().get();
      Recipient destination = db.RecipientsTable.get(verifiedMessage.getDestination());
      TrustLevel trustLevel = TrustLevel.fromVerifiedState(verifiedMessage.getVerified());
      account.getProtocolStore().saveIdentity(destination, verifiedMessage.getIdentityKey(), trustLevel);
      logger.info("received verified state update from device {}", content.getSenderDevice());
    }

    if (syncMessage.getKeys().isPresent()) {
      KeysMessage keysMessage = syncMessage.getKeys().get();
      logger.info("received storage keys from device " + content.getSenderDevice());
      if (keysMessage.getStorageService().isPresent()) {
        StorageKey storageKey = keysMessage.getStorageService().get();
        account.setStorageKey(storageKey);
        BackgroundJobRunnerThread.queue(new SyncStorageDataJob(account));
      }
    }

    if (syncMessage.getFetchType().isPresent()) {
      switch (syncMessage.getFetchType().get()) {
      case LOCAL_PROFILE:
        BackgroundJobRunnerThread.queue(new RefreshProfileJob(account, account.getSelf()));
        break;
      case STORAGE_MANIFEST:
        BackgroundJobRunnerThread.queue(new SyncStorageDataJob(account));
        break;
      }
      logger.info("received {} fetch request device {}", syncMessage.getFetchType().get().name(), content.getSenderDevice());
    }

    //      if (syncMessage.getPniIdentity().isPresent()) {
    //        SyncMessage.PniIdentity pniIdentity = syncMessage.getPniIdentity().get();
    //        IdentityKey pniIdentityKey = new IdentityKey(pniIdentity.getPublicKey().toByteArray());
    //        ECPrivateKey pniPrivateKey = Curve.decodePrivatePoint(pniIdentity.getPrivateKey().toByteArray());
    //        account.setPNIIdentityKeyPair(new IdentityKeyPair(pniIdentityKey, pniPrivateKey));
    //        logger.info("received PNI identity key from device {}", content.getSenderDevice());
    //      }
    if (syncMessage.getPniChangeNumber().isPresent()) {
      SyncMessage.PniChangeNumber pniChangeNumber = syncMessage.getPniChangeNumber().get();
      //        account.setPniRegistrationId(pniChangeNumber.registrationId);
      //        account.setPNI(ServiceId.PNI.from());
      logger.info("account phone number has changed to {}", Util.redact(pniChangeNumber.newE164));
    }
  }

  private void handleEndSession(Recipient address) { account.getProtocolStore().deleteAllSessions(address); }

  public void retrieveAttachment(SignalServiceAttachment attachment)
      throws NoSuchAccountException, InvalidMessageException, MissingConfigurationException, SQLException, IOException, ServerNotFoundException, InvalidProxyException {
    if (!attachment.isPointer()) {
      logger.warn("asked to download attachment that is a stream, but no filename provided");
      return;
    }

    File destination = FileUtil.attachmentFile(attachment.asPointer().getRemoteId());
    retrieveAttachment(attachment, destination);
  }

  public void retrieveAttachment(SignalServiceAttachment attachment, File destination)
      throws NoSuchAccountException, InvalidMessageException, MissingConfigurationException, SQLException, IOException, ServerNotFoundException, InvalidProxyException {
    if (attachment.isPointer() && attachment.asPointer().getPreview().isPresent()) {
      // store preview
      File previewFile = FileUtil.attachmentFile(attachment.asPointer().getRemoteId(), "preview");
      try (OutputStream output = new FileOutputStream(previewFile)) {
        byte[] preview = attachment.asPointer().getPreview().get();
        output.write(preview, 0, preview.length);
      } catch (FileNotFoundException e) {
        logger.catching(e);
      }
    }

    if (attachment.isPointer()) {
      final File tmpFile = FileUtil.createTempFile();
      final SignalServiceMessageReceiver messageReceiver = account.getSignalDependencies().getMessageReceiver();
      try (InputStream input = messageReceiver.retrieveAttachment(attachment.asPointer(), tmpFile, ServiceConfig.MAX_ATTACHMENT_SIZE)) {
        saveAttachment(input, destination);
      } finally {
        try {
          Files.delete(tmpFile.toPath());
        } catch (IOException e) {
          logger.warn("Failed to delete received attachment temp file \"{}\": {}", tmpFile, e.getMessage());
        }
      }
    } else {
      try (SignalServiceAttachmentStream stream = attachment.asStream()) {
        try (InputStream input = stream.getInputStream()) {
          saveAttachment(input, destination);
        }
      }
    }
  }

  private void saveAttachment(InputStream input, File destination) throws IOException {
    try (OutputStream output = new FileOutputStream(destination)) {
      byte[] buffer = new byte[4096];
      int read;

      while ((read = input.read(buffer)) != -1) {
        output.write(buffer, 0, read);
      }
    }
  }

  private InputStream retrieveAttachmentAsStream(SignalServiceAttachmentPointer pointer, File tmpFile)
      throws IOException, InvalidMessageException, MissingConfigurationException, NoSuchAccountException, SQLException, ServerNotFoundException, InvalidProxyException {
    final SignalServiceMessageReceiver messageReceiver = account.getSignalDependencies().getMessageReceiver();
    return messageReceiver.retrieveAttachment(pointer, tmpFile, ServiceConfig.MAX_ATTACHMENT_SIZE);
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
