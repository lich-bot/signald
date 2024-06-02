/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.exceptions;

import io.finn.signald.db.Recipient;

public class NoProfileKeyException extends Exception {

  private Recipient recipient;
  public NoProfileKeyException(Recipient recipient) {
    super("requested profile key is not available for " + recipient.toRedactedString());
    this.recipient = recipient;
  }

  public Recipient getRecipient() { return recipient; }
}
