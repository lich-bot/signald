/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.exceptions;

import java.util.UUID;

public class StreamNotReadyException extends Exception {
  private final UUID streamId;
  public StreamNotReadyException(UUID streamId) {
    super("stream not ready");
    this.streamId = streamId;
  }

  public UUID getStreamId() { return streamId; }
}
