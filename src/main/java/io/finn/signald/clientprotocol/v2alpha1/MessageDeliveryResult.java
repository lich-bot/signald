/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.clientprotocol.v1.JsonAddress;
import io.finn.signald.clientprotocol.v1.SendSuccess;
import org.asamk.signal.util.Hex;
import org.whispersystems.signalservice.api.messages.SendMessageResult;

public class MessageDeliveryResult {
  public JsonAddress address;
  public SendSuccess success;
  @ExampleValue("false") public boolean networkFailure;
  @ExampleValue("false") public boolean unregisteredFailure;
  public String identityFailure;

  public MessageDeliveryResult(SendMessageResult result) {
    address = new JsonAddress(result.getAddress());
    if (result.getSuccess() != null) {
      success = new SendSuccess(result.getSuccess());
    }
    networkFailure = result.isNetworkFailure();
    unregisteredFailure = result.isUnregisteredFailure();
    if (result.getIdentityFailure() != null) {
      identityFailure = Hex.toStringCondensed(result.getIdentityFailure().getIdentityKey().serialize()).trim();
    }
  }
}
