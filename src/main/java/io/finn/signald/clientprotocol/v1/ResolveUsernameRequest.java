/*
 * Copyright 2024 signald contributors
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
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import org.signal.libsignal.usernames.BaseUsernameException;
import org.signal.libsignal.usernames.Username;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.exceptions.UsernameIsNotAssociatedWithAnAccountException;

@ProtocolType("resolve_username")
@Doc("look up a given username and returns the corresponding ACI if one exists")
@ErrorDoc(error = UsernameIsNotAssociatedWithAnAccountError.class, doc = "the username is not currently associated with an account in Signal")
public class ResolveUsernameRequest implements RequestType<String> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("The identifier of the account to interact with") @Required public String account;

  @Doc("the username to lookup") @Required public String username;

  @Override
  public String run(Request request)
      throws NoSuchAccountError, SQLError, InternalError, ServerNotFoundError, InvalidProxyError, UsernameError, UsernameIsNotAssociatedWithAnAccountError {
    Account a = Common.getAccount(account);

    Username u;
    try {
      u = new Username(username);
    } catch (BaseUsernameException ex) {
      throw new UsernameError(ex);
    }

    ServiceId.ACI aci;
    try {
      aci = a.getSignalDependencies().getAccountManager().getAciByUsername(u);
    } catch (UsernameIsNotAssociatedWithAnAccountException e) {
      throw new UsernameIsNotAssociatedWithAnAccountError();
    } catch (IOException e) {
      throw new InternalError("unexpected error getting aci by username", e);
    } catch (SQLException e) {
      throw new SQLError(e);
    } catch (ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (InvalidProxyException e) {
      throw new InvalidProxyError(e);
    } catch (NoSuchAccountException e) {
      throw new NoSuchAccountError(e);
    }

    return aci.toString();
  }
}
