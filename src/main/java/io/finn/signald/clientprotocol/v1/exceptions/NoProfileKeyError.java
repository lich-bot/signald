/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1.exceptions;

import io.finn.signald.clientprotocol.v1.JsonAddress;
import io.finn.signald.exceptions.NoProfileKeyException;

public class NoProfileKeyError extends ExceptionWrapper {

  public JsonAddress recipient;
  public NoProfileKeyError(NoProfileKeyException e) {
    super(e);
    recipient = new JsonAddress(e.getRecipient());
  }
}
