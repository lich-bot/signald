/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import io.finn.signald.Account;
import io.finn.signald.Manager;
import io.finn.signald.SignalDependencies;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.*;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.InternalError;
import io.finn.signald.db.AccountsTable;
import io.finn.signald.db.Recipient;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSendPermissionException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.groups.GroupIdentifier;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.signalservice.api.messages.SendMessageResult;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.util.Base64;

/* Common is a collection of wrapper functions that call common functions
 * and convert their exceptions to documented v1 exceptions
 */
public class Common {
  static Manager getManager(String identifier) throws NoSuchAccountError, ServerNotFoundError, InvalidProxyError, InternalError {
    if (identifier.startsWith("+")) {
      UUID accountID;
      try {
        accountID = AccountsTable.getUUID(identifier);
      } catch (NoSuchAccountException e) {
        throw new NoSuchAccountError(e);
      } catch (SQLException e) {
        throw new InternalError("error getting manager", e);
      }
      return getManager(accountID);
    } else {
      return getManager(UUID.fromString(identifier));
    }
  }

  public static Manager getManager(UUID account) throws NoSuchAccountError, ServerNotFoundError, InvalidProxyError, InternalError {
    Manager m;
    try {
      m = Manager.get(account);
    } catch (NoSuchAccountException e) {
      throw new NoSuchAccountError(e);
    } catch (InvalidProxyException e) {
      throw new InvalidProxyError(e);
    } catch (ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (IOException | SQLException | InvalidKeyException e) {
      throw new InternalError("error getting manager", e);
    }
    return m;
  }

  public static List<SendMessageResult> send(Manager manager, SignalServiceDataMessage.Builder messageBuilder, Recipient recipient, String groupId)
      throws InvalidRecipientError, UnknownGroupError, NoSendPermissionError, InternalError, InvalidRequestError {
    GroupIdentifier groupIdentifier = null;
    if (groupId != null) {
      try {
        groupIdentifier = new GroupIdentifier(Base64.decode(groupId));
      } catch (InvalidInputException | IOException e) {
        throw new InvalidRequestError(e.getMessage());
      }
    }

    try {
      return manager.send(messageBuilder, recipient, groupIdentifier, null);
    } catch (io.finn.signald.exceptions.InvalidRecipientException e) {
      throw new InvalidRecipientError();
    } catch (io.finn.signald.exceptions.UnknownGroupException e) {
      throw new UnknownGroupError();
    } catch (NoSendPermissionException e) {
      throw new NoSendPermissionError();
    } catch (IOException | SQLException | InvalidInputException e) {
      throw new InternalError("error sending message", e);
    }
  }

  public static Account getAccount(String identifier) throws NoSuchAccountError, InternalError {
    UUID accountUUID = UUID.fromString(identifier);
    Account account = new Account(accountUUID);
    try {
      if (!account.exists()) {
        throw new NoSuchAccountError(identifier);
      }
    } catch (SQLException e) {
      throw new InternalError("error getting account", e);
    }
    return account;
  }

  public static SignalDependencies getDependencies(UUID accountUUID) throws InvalidProxyError, ServerNotFoundError, InternalError, NoSuchAccountError {
    try {
      return SignalDependencies.get(accountUUID);
    } catch (SQLException | IOException e) {
      throw new InternalError("error reading local account state", e);
    } catch (ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (InvalidProxyException e) {
      throw new InvalidProxyError(e);
    } catch (NoSuchAccountException e) {
      throw new NoSuchAccountError(e);
    }
  }
}
