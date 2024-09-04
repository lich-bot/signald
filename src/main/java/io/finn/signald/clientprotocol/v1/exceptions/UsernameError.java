/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1.exceptions;

import org.signal.libsignal.usernames.BaseUsernameException;

public class UsernameError extends ExceptionWrapper {
  public UsernameError(BaseUsernameException ex) { super(ex); }
}
