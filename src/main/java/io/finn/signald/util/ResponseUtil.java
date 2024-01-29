/*
 * Copyright 2024 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.util;

import java.io.IOException;
import org.whispersystems.signalservice.internal.ServiceResponse;

public class ResponseUtil {
  public static <T> T handleResponseException(final ServiceResponse<T> response) throws IOException {
    final var throwableOptional = response.getExecutionError().or(response::getApplicationError);
    if (throwableOptional.isPresent()) {
      if (throwableOptional.get() instanceof IOException) {
        throw(IOException) throwableOptional.get();
      } else {
        throw new IOException(throwableOptional.get());
      }
    }
    return response.getResult().orElse(null);
  }
}
