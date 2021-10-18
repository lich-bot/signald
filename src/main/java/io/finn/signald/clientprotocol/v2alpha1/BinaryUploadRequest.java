/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ProtocolType;
import io.finn.signald.annotations.Required;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;

@ProtocolType("binary_upload")
public class BinaryUploadRequest implements RequestType<BinaryTransfer> {
  @Required @Doc("the size of the file to be transferred, in bytes") public long size;

  @Override
  public BinaryTransfer run(Request request) throws InternalError {
    return new BinaryTransfer(size);
  }
}
