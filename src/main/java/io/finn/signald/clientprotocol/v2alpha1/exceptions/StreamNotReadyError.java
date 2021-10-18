/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1.exceptions;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.exceptions.StreamNotReadyException;

public class StreamNotReadyError extends ExceptionWrapper {
  @JsonProperty("transfer_id") public final String transferId;
  public StreamNotReadyError(StreamNotReadyException e) {
    super(e);
    transferId = e.getStreamId().toString();
  }
}
