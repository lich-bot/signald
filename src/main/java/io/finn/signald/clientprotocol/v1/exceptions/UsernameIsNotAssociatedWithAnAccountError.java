/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1.exceptions;

import org.whispersystems.signalservice.api.push.exceptions.UsernameIsNotAssociatedWithAnAccountException;

public class UsernameIsNotAssociatedWithAnAccountError extends ExceptionWrapper {
  public UsernameIsNotAssociatedWithAnAccountError() { super("username is not associated with an account"); }
}
