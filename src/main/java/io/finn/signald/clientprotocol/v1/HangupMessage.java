/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.annotations.Deprecated;
import io.finn.signald.annotations.Doc;

public class HangupMessage {
  public final long id;
  public final String type;
  @JsonProperty("device_id") public final int deviceId;
  @Doc("seems to have been dropped from libsignal, will always be false") public final boolean legacy = false;

  public HangupMessage(org.whispersystems.signalservice.api.messages.calls.HangupMessage message) {
    id = message.getId();
    type = message.getType().getCode();
    deviceId = message.getDeviceId();
  }
}
