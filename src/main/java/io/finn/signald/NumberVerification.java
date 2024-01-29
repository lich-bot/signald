/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import io.finn.signald.util.ResponseUtil;
import java.io.IOException;
import java.util.Locale;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.account.AccountAttributes;
import org.whispersystems.signalservice.api.account.PreKeyCollection;
import org.whispersystems.signalservice.internal.ServiceResponse;
import org.whispersystems.signalservice.internal.push.RegistrationSessionMetadataResponse;
import org.whispersystems.signalservice.internal.push.VerifyAccountResponse;

public class NumberVerification {
  private final SignalServiceAccountManager accountManager;
  private String sessionId;

  NumberVerification(SignalServiceAccountManager accountManager) { this.accountManager = accountManager; }

  public String getSession() throws IOException {
    RegistrationSessionMetadataResponse session;
    if (sessionId == null) {
      session = ResponseUtil.handleResponseException(accountManager.createRegistrationSession(null, "", "")); // TODO: what are mcc and mnc properties here? can we set them?
    } else {
      session = ResponseUtil.handleResponseException(accountManager.getRegistrationSession(sessionId));
    }

    sessionId = session.getBody().getId();
    return sessionId;
  }

  public RegistrationSessionMetadataResponse submitCaptcha(String captcha) throws IOException {
    ServiceResponse<RegistrationSessionMetadataResponse> response = accountManager.submitCaptchaToken(getSessionId(), captcha);
    return ResponseUtil.handleResponseException(response);
  }

  public RegistrationSessionMetadataResponse requestVerificationCode(boolean voice) throws IOException {
    ServiceResponse<RegistrationSessionMetadataResponse> response;
    if (voice) {
      response = accountManager.requestVoiceVerificationCode(getSessionId(), Locale.getDefault(), false);
    } else {
      response = accountManager.requestSmsVerificationCode(getSessionId(), Locale.getDefault(), false);
    }
    return ResponseUtil.handleResponseException(response);
  }

  public RegistrationSessionMetadataResponse submitVerificationCode(String code) throws IOException {
    code = code.replace("-", "");
    return ResponseUtil.handleResponseException(accountManager.verifyAccount(code, getSessionId()));
  }

  public VerifyAccountResponse register(AccountAttributes attributes, PreKeyCollection aciPreKeys, PreKeyCollection pniPreKeys, boolean skipDeviceTransfer) throws IOException {
    ServiceResponse<VerifyAccountResponse> response = accountManager.registerAccount(getSessionId(), null, attributes, aciPreKeys, pniPreKeys, null, skipDeviceTransfer);
    return ResponseUtil.handleResponseException(response);
  }

  // returns the session ID, creating a new one if none exists
  private String getSessionId() throws IOException {
    if (sessionId == null) {
      RegistrationSessionMetadataResponse response = ResponseUtil.handleResponseException(accountManager.createRegistrationSession(null, "", ""));
      sessionId = response.getBody().getId();
    }

    return sessionId;
  }
}
