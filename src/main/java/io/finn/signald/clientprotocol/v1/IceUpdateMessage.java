/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.protobuf.InvalidProtocolBufferException;
import io.finn.signald.annotations.Doc;
import org.apache.logging.log4j.LogManager;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos;
import org.whispersystems.util.Base64;

public class IceUpdateMessage {
  public final long id;
  @Doc("the base64 encoded protobuf value. deprecated.") @Deprecated public final String opaque;
  public final String sdp;
  public String mid;
  public int line;

  public IceUpdateMessage(org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage message) {
    id = message.getId();
    opaque = Base64.encodeBytes(message.getOpaque());
    sdp = message.getSdp();
    try {
      SignalServiceProtos.CallMessage.IceUpdate update = SignalServiceProtos.CallMessage.IceUpdate.parseFrom(message.getOpaque());
      mid = update.getMid();
      line = update.getLine();
    } catch (InvalidProtocolBufferException e) {
      LogManager.getLogger().error("error parsing ice update proto: ", e);
    }
  }

  @JsonIgnore
  public org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage getProtocolMessage() {
    SignalServiceProtos.CallMessage.IceUpdate.Builder builder = SignalServiceProtos.CallMessage.IceUpdate.newBuilder();
    builder.setId(id);
    builder.setSdp(sdp);
    builder.setMid(mid);
    builder.setLine(line);

    return new org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage(id, builder.build().toByteArray(), sdp);
  }
}
