/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.ProofRequiredError;
import org.asamk.signal.util.Hex;
import org.whispersystems.signalservice.api.messages.SendMessageResult;

public class MessageDeliveryResult {
  @JsonProperty("remote_user") public String remoteUser;
  public SendSuccess success;
  @JsonProperty("network_failure") @ExampleValue("false") public boolean networkFailure;
  @JsonProperty("unregistered_failure") @ExampleValue("false") public boolean unregisteredFailure;
  @JsonProperty("identity_failure") public String identityFailure;
  @JsonProperty("proof_required_failure") public ProofRequiredError proofRequiredFailure;

  public MessageDeliveryResult(SendMessageResult result) {
    remoteUser = result.getAddress().getUuid().toString();
    if (result.getSuccess() != null) {
      success = new SendSuccess(result.getSuccess());
    }
    networkFailure = result.isNetworkFailure();
    unregisteredFailure = result.isUnregisteredFailure();
    if (result.getIdentityFailure() != null) {
      identityFailure = Hex.toStringCondensed(result.getIdentityFailure().getIdentityKey().serialize()).trim();
    }
    if (result.getProofRequiredFailure() != null) {
      proofRequiredFailure = new ProofRequiredError(result.getProofRequiredFailure());
    }
  }
}
