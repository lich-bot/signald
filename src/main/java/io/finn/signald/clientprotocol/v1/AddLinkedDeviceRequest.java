/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.Account;
import io.finn.signald.Empty;
import io.finn.signald.LinkedDevices;
import io.finn.signald.Manager;
import io.finn.signald.annotations.*;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.sql.SQLException;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.zkgroup.InvalidInputException;

@ProtocolType("add_device")
@ErrorDoc(error = InvalidRequestError.class, doc = "caused by syntax errors with the provided linking URI")
@Doc("Link a new device to a local Signal account")
public class AddLinkedDeviceRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("The account to interact with") @Required public String account;

  @ExampleValue(ExampleValue.LINKING_URI) @Doc("the sgnl://linkdevice uri provided (typically in qr code form) by the new device") @Required public String uri;

  @Override
  public Empty run(Request request)
      throws NoSuchAccountError, ServerNotFoundError, InvalidProxyError, InvalidRequestError, InternalError, AuthorizationFailedError, SQLError, NetworkError {
    Account a = Common.getAccount(account);
    try {
      LinkedDevices.add(a, new URI(uri));
    } catch (UnknownHostException e) {
      throw new NetworkError(e);
    } catch (IOException | InvalidKeyException | SQLException e) {
      throw new InternalError("error adding device", e);
    } catch (URISyntaxException e) {
      throw new InvalidRequestError(e.getMessage());
    } catch (NoSuchAccountException e) {
      throw new NoSuchAccountError(e);
    } catch (ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (InvalidProxyException e) {
      throw new InvalidProxyError(e);
    }
    return new Empty();
  }
}
