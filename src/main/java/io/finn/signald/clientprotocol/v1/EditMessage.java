/*
 * Copyright 2023 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;
import org.whispersystems.signalservice.api.messages.SignalServiceEditMessage;
import org.whispersystems.signalservice.api.push.ServiceId;

public class EditMessage {
  public long target;
  public JsonDataMessage message;

  public EditMessage(SignalServiceEditMessage msg, ServiceId.ACI aci)
      throws NoSuchAccountError, ServerNotFoundError, NetworkError, AuthorizationFailedError, InvalidProxyError, InternalError {
    target = msg.getTargetSentTimestamp();
    message = new JsonDataMessage(msg.getDataMessage(), aci);
  }
}
