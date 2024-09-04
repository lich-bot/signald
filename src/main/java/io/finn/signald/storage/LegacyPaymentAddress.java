/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.storage;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.IOException;
import org.signal.core.util.Base64;
import org.whispersystems.signalservice.internal.push.PaymentAddress;
@Deprecated
public class LegacyPaymentAddress {
  @JsonProperty private String address;

  private LegacyPaymentAddress() {}

  public LegacyPaymentAddress(PaymentAddress a) { address = Base64.encodeWithPadding(a.encode()); }

  public PaymentAddress get() throws IOException { return PaymentAddress.ADAPTER.decode(Base64.decode(address)); }
}
