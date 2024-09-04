/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.clientprotocol.v1;

import java.util.List;
import org.whispersystems.signalservice.api.RemoteConfigResult;

public class RemoteConfigList {
  public final List<RemoteConfig> config;
  public final Long timestamp;

  public RemoteConfigList(RemoteConfigResult result) {
    config = result.getConfig().entrySet().stream().map(e -> new RemoteConfig(e.getKey(), String.valueOf(e.getValue()))).toList();
    timestamp = result.getServerEpochTimeSeconds();
  }
}
