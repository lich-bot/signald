/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.BuildConfig;
import io.finn.signald.RegistrationManager;
import io.finn.signald.annotations.*;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import java.io.IOException;
import java.lang.InternalError;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.whispersystems.signalservice.api.push.exceptions.CaptchaRequiredException;
import org.whispersystems.signalservice.api.push.exceptions.RateLimitException;
import org.whispersystems.signalservice.api.push.exceptions.TokenNotAcceptedException;

@ProtocolType("register")
@Doc("begin the account registration process by requesting a phone number verification code. when the code is received, submit it with a verify request")
@ErrorDoc(error = TokenNotAcceptedError.class, doc = "captcha was rejected, in testing this seems to happen when a captcha token is re-used")
public class RegisterRequest implements RequestType<Account> {
  @ExampleValue(ExampleValue.LOCAL_PHONE_NUMBER) @Doc("the e164 phone number to register with") @Required public String account;

  @Doc("set to true to request a voice call instead of an SMS for verification") public boolean voice = false;

  @Doc("See https://signald.org/articles/captcha/") public String captcha;

  @Doc("The identifier of the server to use. Leave blank for default (usually Signal production servers but configurable at build time)")
  public String server = BuildConfig.DEFAULT_SERVER_UUID;

  @Override
  public Account run(Request request) throws CaptchaRequiredError, ServerNotFoundError, InvalidProxyError, RateLimitError, TokenNotAcceptedError {
    RegistrationManager m;
    try {
      m = RegistrationManager.get(account, UUID.fromString(server));
    } catch (io.finn.signald.exceptions.InvalidProxyException e) {
      throw new InvalidProxyError(e);
    } catch (io.finn.signald.exceptions.ServerNotFoundException e) {
      throw new ServerNotFoundError(e);
    } catch (SQLException | IOException e) {
      throw new InternalError("error getting registration manager", e);
    }

    if (captcha != null && captcha.startsWith("signalcaptcha://")) {
      captcha = captcha.substring(16);
    }

    try {
      m.register(voice, Optional.ofNullable(captcha), UUID.fromString(server));
    } catch (CaptchaRequiredException e) {
      throw new CaptchaRequiredError();
    } catch (RateLimitException e) {
      throw new RateLimitError(e);
    } catch (TokenNotAcceptedException e) {
      throw new TokenNotAcceptedError(e);
    } catch (InvalidInputException | IOException | SQLException e) {
      throw new InternalError("error registering with server", e);
    }

    return new Account(m);
  }
}
