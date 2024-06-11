/*
 * Copyright 2023 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.whispersystems.signalservice.internal.push.BodyRange;

public class BodyRangeMessage {
  public int start;
  public int length;
  @JsonProperty("mention_aci") public String mentionAci;
  public String style;

  public BodyRangeMessage(BodyRange msg) {
    start = msg.start;
    length = msg.length;
    mentionAci = msg.mentionAci;
    if (msg.style != null) {
      style = msg.style.toString();
    }
  }

 public BodyRange toBodyRange() {
     return new BodyRange().newBuilder().length(length).start(start).mentionAci(style).build();
  }
}
