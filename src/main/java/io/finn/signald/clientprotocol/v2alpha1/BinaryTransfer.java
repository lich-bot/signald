/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

public class BinaryTransfer {
  public long size;
  public String identifier;

  public BinaryTransfer(long size) {
    this.size = size;
    io.finn.signald.binarytransfers.BinaryTransfer transfer = new io.finn.signald.binarytransfers.BinaryTransfer(size);
    identifier = transfer.getTransferID().toString();
  }
}
