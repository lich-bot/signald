/*
 * Copyright (C) 2021 Finn Herzfeld
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

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.JsonAttachment;
import io.finn.signald.JsonStickerPackOperationMessage;
import io.finn.signald.clientprotocol.v1.exceptions.InvalidProxyException;
import io.finn.signald.clientprotocol.v1.exceptions.NoSuchAccount;
import io.finn.signald.clientprotocol.v1.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.signalservice.api.messages.multidevice.*;

public class JsonSyncMessage {
  public JsonSentTranscriptMessage sent;
  public JsonAttachment contacts;
  public boolean contactsComplete;
  public JsonAttachment groups;
  public JsonBlockedListMessage blockedList;
  public String request;
  public List<JsonReadMessage> readMessages;
  public JsonViewOnceOpenMessage viewOnceOpen;
  public JsonVerifiedMessage verified;
  public ConfigurationMessage configuration;
  public List<JsonStickerPackOperationMessage> stickerPackOperations;
  public String fetchType;
  public JsonMessageRequestResponseMessage messageRequestResponse;

  public JsonSyncMessage(SignalServiceSyncMessage syncMessage, String username)
      throws IOException, NoSuchAccount, SQLException, InvalidKeyException, InvalidProxyException, ServerNotFoundException {
    if (syncMessage.getSent().isPresent()) {
      this.sent = new JsonSentTranscriptMessage(syncMessage.getSent().get(), username);
    }

    if (syncMessage.getContacts().isPresent()) {
      ContactsMessage c = syncMessage.getContacts().get();
      try {
        contacts = new JsonAttachment(c.getContactsStream(), username);
      } catch (io.finn.signald.exceptions.NoSuchAccountException e) {
        throw new NoSuchAccount(e);
      } catch (io.finn.signald.exceptions.InvalidProxyException e) {
        throw new InvalidProxyException(e);
      } catch (io.finn.signald.exceptions.ServerNotFoundException e) {
        throw new ServerNotFoundException(e);
      }
      contactsComplete = c.isComplete();
    }

    if (syncMessage.getGroups().isPresent()) {
      try {
        groups = new JsonAttachment(syncMessage.getGroups().get(), username);
      } catch (io.finn.signald.exceptions.NoSuchAccountException e) {
        throw new NoSuchAccount(e);
      } catch (io.finn.signald.exceptions.InvalidProxyException e) {
        throw new InvalidProxyException(e);
      } catch (io.finn.signald.exceptions.ServerNotFoundException e) {
        throw new ServerNotFoundException(e);
      }
    }

    if (syncMessage.getBlockedList().isPresent()) {
      blockedList = new JsonBlockedListMessage(syncMessage.getBlockedList().get());
    }

    if (syncMessage.getRequest().isPresent()) {
      request = syncMessage.getRequest().get().getRequest().getType().name();
    }

    if (syncMessage.getRead().isPresent()) {
      readMessages = new ArrayList<>();
      for (ReadMessage r : syncMessage.getRead().get()) {
        readMessages.add(new JsonReadMessage(r));
      }
    }

    if (syncMessage.getViewOnceOpen().isPresent()) {
      viewOnceOpen = new JsonViewOnceOpenMessage(syncMessage.getViewOnceOpen().get());
    }

    if (syncMessage.getVerified().isPresent()) {
      verified = new JsonVerifiedMessage(syncMessage.getVerified().get());
    }

    if (syncMessage.getConfiguration().isPresent()) {
      configuration = syncMessage.getConfiguration().get();
    }

    if (syncMessage.getStickerPackOperations().isPresent()) {
      stickerPackOperations = new ArrayList<>();
      for (StickerPackOperationMessage message : syncMessage.getStickerPackOperations().get()) {
        stickerPackOperations.add(new JsonStickerPackOperationMessage(message));
      }
    }

    if (syncMessage.getFetchType().isPresent()) {
      fetchType = syncMessage.getFetchType().get().name();
    }

    if (syncMessage.getMessageRequestResponse().isPresent()) {
      messageRequestResponse = new JsonMessageRequestResponseMessage(syncMessage.getMessageRequestResponse().get());
    }
  }
}
