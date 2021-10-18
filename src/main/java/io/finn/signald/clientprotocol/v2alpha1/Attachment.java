/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.binarytransfers.BinaryTransfer;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.InternalError;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.StreamNotReadyError;
import io.finn.signald.exceptions.StreamNotReadyException;
import java.io.IOException;
import java.util.UUID;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment;

@Doc("a file attached to a message")
public class Attachment {
  @JsonProperty("content_type") @ExampleValue("image/jpeg") public String contentType;
  @JsonProperty("original_filename") public String originalFilename;
  @JsonProperty("voice_note") public boolean voiceNote;
  public boolean borderless;
  public boolean gif;
  public Integer width;
  public Integer height;
  public String caption;
  @JsonProperty("blur_hash") public String blueHash;
  @JsonProperty("upload_timestamp") public Long uploadTimestamp;
  @JsonProperty("transfer_id") public String transferId;

  @JsonIgnore
  public SignalServiceAttachment getSignalServiceAttachment() throws InternalError, StreamNotReadyError {
    BinaryTransfer transfer = BinaryTransfer.get(UUID.fromString(transferId));

    SignalServiceAttachment.Builder builder = SignalServiceAttachment.newStreamBuilder();
    try {
      builder.withStream(transfer.getInputStream()).withLength(transfer.getSize());
    } catch (IOException e) {
      throw new InternalError("error getting attachment input stream", e);
    } catch (StreamNotReadyException e) {
      throw new StreamNotReadyError(e);
    }

    if (originalFilename != null) {
      builder.withFileName(originalFilename);
    }

    if (contentType != null) {
      builder.withContentType(contentType);
    }

    if (voiceNote) {
      builder.withVoiceNote(true);
    }

    if (borderless) {
      builder.withBorderless(true);
    }

    if (gif) {
      builder.withGif(true);
    }

    if (width != null) {
      builder.withWidth(width);
    }

    if (height != null) {
      builder.withHeight(height);
    }

    if (caption != null) {
      builder.withCaption(caption);
    }

    if (blueHash != null) {
      builder.withBlurHash(blueHash);
    }

    if (uploadTimestamp == null) {
      uploadTimestamp = System.currentTimeMillis();
    }
    builder.withUploadTimestamp(uploadTimestamp);

    return builder.build();
  }

  @JsonIgnore
  public BinaryTransfer getTransfer() {
    return BinaryTransfer.get(UUID.fromString(transferId));
  }
}
