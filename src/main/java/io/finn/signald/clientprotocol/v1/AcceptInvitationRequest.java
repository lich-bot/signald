/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.Account;
import io.finn.signald.annotations.*;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoProfileKeyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential;
import org.signal.storageservice.protos.groups.GroupChange;
import org.whispersystems.signalservice.api.groupsv2.GroupsV2Operations;
import org.whispersystems.signalservice.api.util.UuidUtil;

@ProtocolType("accept_invitation")
@Doc("Accept a v2 group invitation. Note that you must have a profile name set to join groups.")
@ErrorDoc(error = AuthorizationFailedError.class, doc = AuthorizationFailedError.DEFAULT_ERROR_DOC)
@ErrorDoc(error = GroupPatchNotAcceptedError.class, doc = GroupPatchNotAcceptedError.DEFAULT_ERROR_DOC)
public class AcceptInvitationRequest implements RequestType<JsonGroupV2Info> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("The account to interact with") @Required public String account;

  @ExampleValue(ExampleValue.GROUP_ID) @Required public String groupID;

  @Override
  public JsonGroupV2Info run(Request request) throws NoSuchAccountError, OwnProfileKeyDoesNotExistError, ServerNotFoundError, InvalidProxyError, UnknownGroupError, InternalError,
                                                     InvalidRequestError, AuthorizationFailedError, SQLError, GroupPatchNotAcceptedError, NoProfileKeyError {
    Account a = Common.getAccount(account);

    ExpiringProfileKeyCredential ownExpiringProfileKeyCredential;
    try {
      ownExpiringProfileKeyCredential = a.getExpiringProfileKeyCredential(a.getSelf());
    } catch (IOException | SQLException | InvalidInputException | InvalidKeyException e) {
      throw new InternalError("error getting own profile key credential", e);
    } catch (NoSuchAccountException e) {
      throw new NoSuchAccountError(e);
    } catch (NoProfileKeyException e) {
      throw new NoProfileKeyError(e);
    } catch (ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (InvalidProxyException e) {
      throw new InvalidProxyError(e);
    }

    if (ownExpiringProfileKeyCredential == null) {
      throw new OwnProfileKeyDoesNotExistError();
    }

    var group = Common.getGroup(a, groupID);

    GroupsV2Operations.GroupOperations groupOperations = Common.getGroupOperations(a, group);
    GroupChange.Actions.Builder change = groupOperations.createAcceptInviteChange(ownExpiringProfileKeyCredential);
    change.sourceServiceId(UuidUtil.toByteString(a.getUUID()));

    Common.updateGroup(a, group, change);

    return group.getJsonGroupV2Info();
  }
}
