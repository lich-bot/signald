/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.signal.core.util.Base64;
import org.whispersystems.signalservice.api.messages.SignalServiceTypingMessage;

public class TypingMessage {
  public String action;
  public long timestamp;
  @JsonProperty("group_id") public String groupId;

  public TypingMessage(SignalServiceTypingMessage typingMessage) {
    action = typingMessage.getAction().name();
    timestamp = typingMessage.getTimestamp();
    if (typingMessage.getGroupId().isPresent()) {
      groupId = Base64.encodeBytes(typingMessage.getGroupId().get());
    }
  }
}
