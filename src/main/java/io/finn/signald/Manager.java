/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */
package io.finn.signald;

import io.finn.signald.clientprotocol.v1.JsonGroupV2Info;
import io.finn.signald.db.Database;
import io.finn.signald.db.IGroupsTable;
import io.finn.signald.db.IIdentityKeysTable;
import io.finn.signald.db.Recipient;
import io.finn.signald.exceptions.*;
import io.finn.signald.jobs.RefreshPreKeysJob;
import io.finn.signald.jobs.RefreshProfileJob;
import io.finn.signald.util.SafetyNumberHelper;
import io.finn.signald.util.UnidentifiedAccessUtil;
import io.sentry.Sentry;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asamk.signal.TrustLevel;
import org.signal.core.util.Base64;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;
import org.signal.libsignal.protocol.fingerprint.FingerprintParsingException;
import org.signal.libsignal.protocol.fingerprint.FingerprintVersionMismatchException;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.GroupIdentifier;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.storageservice.protos.groups.local.DecryptedTimer;
import org.signal.storageservice.protos.groups.local.EnabledState;
import org.thoughtcrime.securesms.util.Hex;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.SignalSessionLock;
import org.whispersystems.signalservice.api.crypto.ContentHint;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccessPair;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.*;
import org.whispersystems.signalservice.api.messages.multidevice.*;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.push.SyncMessage;

public class Manager {
  private final Logger logger;
  private final SignalServiceConfiguration serviceConfiguration;
  private final ECPublicKey unidentifiedSenderTrustRoot;

  private static final ConcurrentHashMap<String, Manager> managers = new ConcurrentHashMap<>();

  private static String dataPath;
  private static String attachmentsPath;
  private static String avatarsPath;
  private static String stickersPath;

  private final ACI aci;
  private final Account account;
  private final Recipient self;
  private final SignalDependencies dependencies;
  public static Manager get(UUID uuid) throws SQLException, NoSuchAccountException, IOException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    return get(ACI.from(uuid));
  }

  public static Manager get(ACI aci) throws SQLException, NoSuchAccountException, IOException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    return get(aci, false);
  }
  public static Manager get(ACI aci, boolean offline)
      throws SQLException, NoSuchAccountException, IOException, InvalidKeyException, ServerNotFoundException, InvalidProxyException {
    Manager m;
    synchronized (managers) {
      if (managers.containsKey(aci.toString())) {
        return managers.get(aci.toString());
      }
      m = new Manager(aci);
      managers.put(aci.toString(), m);
    }

    if (!offline) {
      Account account = new Account(aci);
      RefreshPreKeysJob.runIfNeeded(account);
      account.refreshIfNeeded();
      RefreshProfileJob.queueIfNeeded(account, account.getSelf());
    }
    return m;
  }

  public static Manager get(String e164) throws NoSuchAccountException, SQLException, InvalidProxyException, ServerNotFoundException, InvalidKeyException, IOException {
    UUID uuid = Database.Get().AccountsTable.getUUID(e164);
    return Manager.get(uuid);
  }

  public static List<Manager> getAll() {
    Logger logger = LogManager.getLogger("manager");
    // We have to create a manager for each account that we're listing, which is all of them :/
    List<Manager> allManagers = new LinkedList<>();
    File[] allAccounts = new File(dataPath).listFiles();
    if (allAccounts == null) {
      return allManagers;
    }
    for (File account : allAccounts) {
      if (!account.isDirectory()) {
        try {
          allManagers.add(Manager.get(account.getName()));
        } catch (IOException | NoSuchAccountException | SQLException | InvalidKeyException | ServerNotFoundException | InvalidProxyException e) {
          logger.warn("Failed to load account from " + account.getAbsolutePath(), e);
        }
      }
    }
    return allManagers;
  }

  Manager(ACI aci) throws IOException, SQLException, InvalidKeyException, ServerNotFoundException, InvalidProxyException, NoSuchAccountException {
    this.aci = aci;
    account = new Account(aci);
    self = account.getSelf();
    logger = LogManager.getLogger("manager-" + Util.redact(aci.toString()));
    var server = Database.Get().AccountsTable.getServer(aci);
    serviceConfiguration = server.getSignalServiceConfiguration();
    unidentifiedSenderTrustRoot = server.getUnidentifiedSenderRoot();
    dependencies = account.getSignalDependencies();
    logger.info("Created a manager for " + Util.redact(aci.toString()));
    synchronized (managers) { managers.put(aci.toString(), this); }
  }

  public static void setDataPath() {
    LogManager.getLogger().debug("Using data folder {}", Config.getDataPath());
    dataPath = Config.getDataPath() + "/data";
    attachmentsPath = Config.getDataPath() + "/attachments";
    avatarsPath = Config.getDataPath() + "/avatars";
    stickersPath = Config.getDataPath() + "/stickers";
  }

  public Account getAccount() { return account; }

  public UUID getUUID() { return aci.getRawUuid(); }

  public ACI getACI() { return aci; }

  public Recipient getOwnRecipient() { return self; }

  public IdentityKey getIdentity() { return account.getProtocolStore().getIdentityKeyPair().getPublicKey(); }

  //  private String getMessageCachePath() throws NoSuchAccountException, SQLException { return dataPath + "/" + account.getE164() + ".d/msg-cache"; }

  //  public static void createPrivateDirectories(String path) throws IOException {
  //    final Path file = new File(path).toPath();
  //    try {
  //      Set<PosixFilePermission> perms = EnumSet.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE, GROUP_READ, GROUP_WRITE, GROUP_EXECUTE);
  //      Files.createDirectories(file, PosixFilePermissions.asFileAttribute(perms));
  //    } catch (UnsupportedOperationException e) {
  //      Files.createDirectories(file);
  //    }
  //  }

  public SignalServiceAccountManager getAccountManager() { return dependencies.getAccountManager(); }

  public List<JsonGroupV2Info> getGroupsV2Info() throws SQLException {
    List<JsonGroupV2Info> groups = new ArrayList<>();
    for (var g : Database.Get(account.getACI()).GroupsTable.getAll()) {
      groups.add(g.getJsonGroupV2Info());
    }
    return groups;
  }

  public List<SendMessageResult> sendGroupV2Message(SignalServiceDataMessage.Builder message, SignalServiceGroupV2 group, List<Recipient> recipients)
      throws IOException, SQLException {
    message.asGroupMessage(group);
    final List<Recipient> membersSend = new ArrayList<>();
    for (Recipient member : recipients) {
      if (!member.equals(self)) {
        membersSend.add(member);
      }
    }

    return sendMessage(message, membersSend);
  }

  // set expiration for a 1-to-1 conversation
  public List<SendMessageResult> setExpiration(Recipient recipient, int expiresInSeconds) throws IOException, SQLException {
    Database.Get(aci).ContactsTable.update(recipient, null, null, null, expiresInSeconds, null);

    SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder().asExpirationUpdate().withExpiration(expiresInSeconds);
    var recipients = new ArrayList<Recipient>(1);
    recipients.add(recipient);
    return sendMessage(messageBuilder, recipients);
  }

  public void requestSyncGroups() throws IOException, SQLException, UntrustedIdentityException {
    SyncMessage.Request r = new SyncMessage.Request.Builder().type(SyncMessage.Request.Type.GROUPS).build();
    SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(r));
    sendSyncMessage(message);
  }

  public void requestSyncContacts() throws IOException, SQLException, UntrustedIdentityException {
    SyncMessage.Request r = new SyncMessage.Request.Builder().type(SyncMessage.Request.Type.CONTACTS).build();
    SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(r));
    sendSyncMessage(message);
  }

  public void requestSyncConfiguration() throws IOException, SQLException, UntrustedIdentityException {
    SyncMessage.Request r = new SyncMessage.Request.Builder().type(SyncMessage.Request.Type.CONFIGURATION).build();
    SignalServiceSyncMessage message = SignalServiceSyncMessage.forRequest(new RequestMessage(r));
    sendSyncMessage(message);
  }

  public void sendSyncMessage(SignalServiceSyncMessage message) throws IOException, org.whispersystems.signalservice.api.crypto.UntrustedIdentityException, SQLException {
    SignalServiceMessageSender messageSender = dependencies.getMessageSender();
    try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
      messageSender.sendSyncMessage(message, getAccessPairFor(self));
    } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
      account.getProtocolStore().handleUntrustedIdentityException(e);
      throw e;
    }
  }

  public SendMessageResult sendTypingMessage(SignalServiceTypingMessage message, Recipient recipient) throws IOException {
    SignalServiceMessageSender messageSender = dependencies.getMessageSender();
    try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
      messageSender.sendTyping(List.of(recipient.getAddress()), getAccessPairFor(List.of(recipient)), message, null);
      return null;
    }
  }

  public SendMessageResult sendReceipt(SignalServiceReceiptMessage message, Recipient recipient) throws IOException, SQLException {
    SignalServiceMessageSender messageSender = dependencies.getMessageSender();
    SignalServiceAddress address = recipient.getAddress();
    try {
      try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
        messageSender.sendReceipt(address, getAccessPairFor(recipient), message, recipient.isNeedsPniSignature());
      }
      if (message.getType() == SignalServiceReceiptMessage.Type.READ) {
        List<ReadMessage> readMessages = new LinkedList<>();
        for (Long ts : message.getTimestamps()) {
          readMessages.add(new ReadMessage(address.getServiceId(), ts));
        }
        try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
          messageSender.sendSyncMessage(SignalServiceSyncMessage.forRead(readMessages), getAccessPairFor(self));
        }
      }
      return null;
    } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
      account.getProtocolStore().handleUntrustedIdentityException(e);
      return SendMessageResult.identityFailure(address, e.getIdentityKey());
    }
  }

  public List<SendMessageResult> sendMessage(SignalServiceDataMessage.Builder messageBuilder, Collection<Recipient> recipients) throws IOException, SQLException {

    ProfileKey profileKey = account.getDB().ProfileKeysTable.getProfileKey(self);
    if (profileKey != null) {
      messageBuilder.withProfileKey(profileKey.serialize());
    }

    SignalServiceDataMessage message = null;

    try {
      SignalServiceMessageSender messageSender = dependencies.getMessageSender();
      message = messageBuilder.build();
      if (message.getGroupContext().isPresent()) {
        try {
          final boolean isRecipientUpdate = false;
          final boolean isUrgent = true;
          List<SignalServiceAddress> recipientAddresses = recipients.stream().map(Recipient::getAddress).collect(Collectors.toList());
          List<SendMessageResult> result;
          result = messageSender.sendDataMessage(recipientAddresses, getAccessPairFor(recipients), isRecipientUpdate, ContentHint.DEFAULT, message,
                                                 SignalServiceMessageSender.LegacyGroupEvents.EMPTY,
                                                 sendResult -> logger.trace("Partial message send result: {}", sendResult.isSuccess()), () -> false, isUrgent);
          for (SendMessageResult r : result) {
            if (r.getIdentityFailure() != null) {
              try {
                Recipient recipient = Database.Get(aci).RecipientsTable.get(r.getAddress());
                account.getProtocolStore().saveIdentity(recipient, r.getIdentityFailure().getIdentityKey(), Config.getNewKeyTrustLevel());
              } catch (SQLException e) {
                logger.error("error storing new identity", e);
                Sentry.captureException(e);
              }
            }
          }
          return result;
        } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
          account.getProtocolStore().handleUntrustedIdentityException(e);
          return Collections.emptyList();
        }
      } else if (recipients.size() == 1 && recipients.contains(self)) {
        final Optional<UnidentifiedAccessPair> unidentifiedAccess = getAccessPairFor(self);
        SentTranscriptMessage transcript = new SentTranscriptMessage(Optional.of(self.getAddress()), message.getTimestamp(), Optional.of(message), message.getExpiresInSeconds(),
                                                                     Collections.singletonMap(self.getAddress().getServiceId(), unidentifiedAccess.isPresent()), false,
                                                                     Optional.empty(), Set.of(), Optional.empty());
        SignalServiceSyncMessage syncMessage = SignalServiceSyncMessage.forSentTranscript(transcript);

        List<SendMessageResult> results = new ArrayList<>(recipients.size());
        try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
          messageSender.sendSyncMessage(syncMessage, unidentifiedAccess);
        } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
          account.getProtocolStore().handleUntrustedIdentityException(e);
          results.add(SendMessageResult.identityFailure(self.getAddress(), e.getIdentityKey()));
        }
        return results;
      } else {
        // Send to all individually, so sync messages are sent correctly
        List<SendMessageResult> results = new ArrayList<>(recipients.size());
        for (Recipient recipient : recipients) {
          var contact = Database.Get(aci).ContactsTable.get(recipient);
          messageBuilder.withExpiration(contact != null ? contact.messageExpirationTime : 0);
          message = messageBuilder.build();
          try {
            if (self.equals(recipient)) { // sending to self
              final Optional<UnidentifiedAccessPair> unidentifiedAccess = getAccessPairFor(recipient);
              SentTranscriptMessage transcript = new SentTranscriptMessage(
                  Optional.of(recipient.getAddress()), message.getTimestamp(), Optional.of(message), message.getExpiresInSeconds(),
                  Collections.singletonMap(recipient.getAddress().getServiceId(), unidentifiedAccess.isPresent()), false, Optional.empty(), Set.of(), Optional.empty());
              SignalServiceSyncMessage syncMessage = SignalServiceSyncMessage.forSentTranscript(transcript);
              try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
                messageSender.sendSyncMessage(syncMessage, unidentifiedAccess);
              }
              //              results.add(SendMessageResult.success(recipient, devices, false, unidentifiedAccess.isPresent(), true, (System.currentTimeMillis() - start),
              //              Optional.absent());
            } else {
              try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
                final boolean isUrgent = true;
                results.add(messageSender.sendDataMessage(recipient.getAddress(), getAccessPairFor(recipient), ContentHint.DEFAULT, message, IndividualSendEventsLogger.INSTANCE,
                                                          isUrgent, recipient.isNeedsPniSignature()));
              } finally {
                logger.debug("send complete");
              }
            }
          } catch (org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
            if (e.getIdentityKey() != null) {
              account.getProtocolStore().handleUntrustedIdentityException(e);
            }
            results.add(SendMessageResult.identityFailure(recipient.getAddress(), e.getIdentityKey()));
          }
        }
        return results;
      }
    } finally {
      if (message != null && message.isEndSession()) {
        for (Recipient recipient : recipients) {
          handleEndSession(recipient);
        }
      }
    }
  }

  //  private SignalServiceContent decryptMessage(SignalServiceEnvelope envelope)
  //      throws InvalidMetadataMessageException, InvalidMetadataVersionException, ProtocolInvalidKeyIdException, ProtocolUntrustedIdentityException,
  //      ProtocolLegacyMessageException,
  //             ProtocolNoSessionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyException, UnsupportedDataMessageException,
  //             org.signal.libsignal.protocol.UntrustedIdentityException, InvalidMessageStructureException, IOException, SQLException, InterruptedException {
  //    try (SignalSessionLock.Lock ignored = dependencies.getSessionLock().acquire()) {
  //      CertificateValidator certificateValidator = new CertificateValidator(unidentifiedSenderTrustRoot);
  //      SignalServiceCipher cipher =
  //          new SignalServiceCipher(self.getAddress(), account.getDeviceId(), account.getProtocolStore(), dependencies.getSessionLock(), certificateValidator);
  //      Semaphore sem = new Semaphore(1);
  //      int watchdogTime = Config.getDecryptionTimeout();
  //      if (watchdogTime > 0) {
  //        sem.acquire();
  //        Thread t = new Thread(() -> {
  //          // a watchdog thread that will make signald exit if decryption takes too long. This behavior is suboptimal, but
  //          // without this it just hangs and breaks in difficult to detect ways.
  //          try {
  //            boolean decryptFinished = sem.tryAcquire(watchdogTime, TimeUnit.SECONDS);
  //            if (!decryptFinished) {
  //              logger.error("took over {} seconds to decrypt, exiting", watchdogTime);
  //              System.exit(101);
  //            }
  //            sem.release();
  //          } catch (InterruptedException e) {
  //            logger.error("error in decryption watchdog thread", e);
  //            Sentry.captureException(e);
  //          }
  //        }, "DecryptWatchdogTimer");
  //
  //        t.start();
  //      }
  //
  //      Histogram.Timer timer = messageDecryptionTime.labels(account.getUUID().toString()).startTimer();
  //      try {
  //        return cipher.decrypt(envelope);
  //      } catch (ProtocolUntrustedIdentityException e) {
  //        if (e.getCause() instanceof org.signal.libsignal.protocol.UntrustedIdentityException) {
  //          org.signal.libsignal.protocol.UntrustedIdentityException identityException = (org.signal.libsignal.protocol.UntrustedIdentityException)e.getCause();
  //          account.getProtocolStore().saveIdentity(identityException.getName(), identityException.getUntrustedIdentity(), Config.getNewKeyTrustLevel());
  //          throw identityException;
  //        }
  //        throw e;
  //      } catch (SelfSendException e) {
  //        logger.debug("Dropping UD message from self (because that's what Signal Android does)");
  //        return null;
  //      } catch (ProtocolInvalidKeyIdException | ProtocolInvalidKeyException | ProtocolNoSessionException | ProtocolInvalidMessageException e) {
  //        logger.debug("Failed to decrypt incoming message: {}", e.getMessage());
  //        Database db = account.getDB();
  //        Recipient sender = db.RecipientsTable.get(e.getSender());
  //        boolean senderCapability = db.ProfileCapabilitiesTable.get(sender, IProfileCapabilitiesTable.SENDER_KEY);
  //        boolean selfCapability = db.ProfileCapabilitiesTable.get(account.getSelf(), IProfileCapabilitiesTable.SENDER_KEY);
  //        if (e.getSenderDevice() != account.getDeviceId() && senderCapability && selfCapability) {
  //          logger.info("incoming message could not be decrypted, asking sender to retry.");
  //          BackgroundJobRunnerThread.queue(new SendRetryMessageRequestJob(account, e, envelope));
  //        } else {
  //          logger.info("incoming message could not be decrypted, queuing session reset with sender");
  //          BackgroundJobRunnerThread.queue(new ResetSessionJob(account, sender));
  //        }
  //        throw e;
  //      } catch (ProtocolDuplicateMessageException e) {
  //        logger.debug("dropping duplicate message");
  //        return null;
  //      } finally {
  //        if (watchdogTime > 0) {
  //          sem.release();
  //        }
  //        double duration = timer.observeDuration();
  //        logger.debug("message decrypted in {} seconds", duration);
  //      }
  //    }
  //  }

  private void handleEndSession(Recipient address) { account.getProtocolStore().deleteAllSessions(address); }

  public List<SendMessageResult> send(SignalServiceDataMessage.Builder message, Recipient recipient, GroupIdentifier recipientGroupId, List<Recipient> members)
      throws IOException, InvalidRecipientException, UnknownGroupException, SQLException, NoSendPermissionException, InvalidInputException {
    if (recipientGroupId != null && recipient == null) {
      Optional<IGroupsTable.IGroup> groupOptional = Database.Get(account.getACI()).GroupsTable.get(recipientGroupId);
      if (groupOptional.isEmpty()) {
        throw new UnknownGroupException();
      }
      var group = groupOptional.get();
      if (members == null) {
        members = group.getMembers();
      }

      if (group.getDecryptedGroup().isAnnouncementGroup == EnabledState.ENABLED && !group.isAdmin(self)) {
        logger.warn("refusing to send to an announcement only group that we're not an admin in.");
        throw new NoSendPermissionException();
      }

      DecryptedTimer timer = group.getDecryptedGroup().disappearingMessagesTimer;
      if (timer != null && timer.duration != 0) {
        message.withExpiration(timer.duration);
      }

      return sendGroupV2Message(message, group.getSignalServiceGroupV2(), members);
    } else if (recipient != null && recipientGroupId == null) {
      List<Recipient> r = new ArrayList<>();
      r.add(recipient);
      return sendMessage(message, r);
    } else {
      throw new InvalidRecipientException();
    }
  }

  @Deprecated
  public SignalServiceMessageReceiver getMessageReceiver() {
    return dependencies.getMessageReceiver();
  }

  public SignalServiceMessageSender getMessageSender() { return dependencies.getMessageSender(); }

  public File getGroupAvatarFile(byte[] groupId) { return new File(avatarsPath, "group-" + Base64.encodeUrlSafeWithoutPadding(groupId)); }

  public File getAttachmentFile(String attachmentId) { return new File(attachmentsPath, attachmentId); }

  public static File getStickerFile(SignalServiceDataMessage.Sticker sticker) {
    String packID = Hex.toStringCondensed(sticker.getPackId());
    String stickerID = String.valueOf(sticker.getStickerId());
    return new File(stickersPath + "/" + packID, stickerID);
  }

  private void sendVerifiedMessage(Recipient destination, IdentityKey identityKey, TrustLevel trustLevel)
      throws IOException, org.whispersystems.signalservice.api.crypto.UntrustedIdentityException, SQLException {
    VerifiedMessage verifiedMessage = new VerifiedMessage(destination.getAddress(), identityKey, trustLevel.toVerifiedState(), System.currentTimeMillis());
    sendSyncMessage(SignalServiceSyncMessage.forVerified(verifiedMessage));
  }

  public List<IIdentityKeysTable.IdentityKeyRow> getIdentities() throws SQLException, InvalidKeyException { return account.getProtocolStore().getIdentities(); }

  public List<IIdentityKeysTable.IdentityKeyRow> getIdentities(Recipient recipient) throws SQLException, InvalidKeyException {
    return account.getProtocolStore().getIdentities(recipient);
  }

  public boolean trustIdentity(Recipient recipient, byte[] fingerprint, TrustLevel level) throws SQLException, InvalidKeyException {
    var ids = account.getProtocolStore().getIdentities(recipient);
    if (ids == null) {
      return false;
    }
    for (var id : ids) {
      if (!Arrays.equals(id.getKey().serialize(), fingerprint)) {
        continue;
      }

      account.getProtocolStore().saveIdentity(recipient, id.getKey(), level);
      try {
        sendVerifiedMessage(recipient, id.getKey(), level);
      } catch (IOException | org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
        logger.catching(e);
      }
      return true;
    }
    return false;
  }

  public boolean trustIdentitySafetyNumber(Recipient recipient, String safetyNumber, TrustLevel level) throws SQLException, InvalidKeyException {
    var ids = account.getProtocolStore().getIdentities(recipient);
    if (ids == null) {
      return false;
    }
    for (var id : ids) {
      if (!safetyNumber.equals(SafetyNumberHelper.computeSafetyNumber(self, getIdentity(), recipient, id.getKey()))) {
        continue;
      }
      account.getProtocolStore().saveIdentity(recipient, id.getKey(), level);

      try {
        sendVerifiedMessage(recipient, id.getKey(), level);
      } catch (IOException | org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
        logger.catching(e);
      }
      return true;
    }
    return false;
  }

  public boolean trustIdentitySafetyNumber(Recipient recipient, byte[] scannedFingerprintData, TrustLevel level)
      throws FingerprintVersionMismatchException, FingerprintParsingException, SQLException, InvalidKeyException {
    var ids = account.getProtocolStore().getIdentities(recipient);
    if (ids == null) {
      return false;
    }
    for (var id : ids) {
      Fingerprint fingerprint = SafetyNumberHelper.computeFingerprint(self, getIdentity(), recipient, id.getKey());
      if (fingerprint == null) {
        throw new IllegalArgumentException("Fingerprint is null");
      }
      if (!fingerprint.getScannableFingerprint().compareTo(scannedFingerprintData)) {
        continue;
      }

      account.getProtocolStore().saveIdentity(recipient, id.getKey(), level);
      try {
        sendVerifiedMessage(recipient, id.getKey(), level);
      } catch (IOException | org.whispersystems.signalservice.api.crypto.UntrustedIdentityException e) {
        logger.catching(e);
      }
      return true;
    }
    return false;
  }

  private List<Optional<UnidentifiedAccessPair>> getAccessPairFor(Collection<Recipient> recipients) {
    List<Optional<UnidentifiedAccessPair>> result = new ArrayList<>(recipients.size());
    for (Recipient recipient : recipients) {
      result.add(getAccessPairFor(recipient));
    }
    return result;
  }

  private Optional<UnidentifiedAccessPair> getAccessPairFor(Recipient recipient) {
    try {
      return new UnidentifiedAccessUtil(aci).getAccessPairFor(recipient);
    } catch (SQLException | IOException | NoSuchAccountException | ServerNotFoundException | InvalidProxyException e) {
      logger.error("unexpected error getting UnidentifiedAccessPair: ", e);
      Sentry.captureException(e);
      return Optional.empty();
    }
  }

  public void deleteAccount() throws IOException, SQLException {
    synchronized (managers) { managers.remove(aci.toString()); }
  }

  public SignalServiceConfiguration getServiceConfiguration() { return serviceConfiguration; }
}
