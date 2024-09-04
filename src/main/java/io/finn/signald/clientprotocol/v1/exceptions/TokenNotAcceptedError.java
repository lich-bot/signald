/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1.exceptions;

import io.finn.signald.annotations.Doc;
import org.whispersystems.signalservice.api.push.exceptions.TokenNotAcceptedException;

public class TokenNotAcceptedError extends ExceptionWrapper {
  public TokenNotAcceptedError(TokenNotAcceptedException e) { super("token was not accepted"); }
}
