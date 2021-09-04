/*
 * Copyright (C) 2021 Finn Herzfeld
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.finn.signald;

import java.util.UUID;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceDataStore;
import org.whispersystems.signalservice.api.SignalWebSocket;
import org.whispersystems.signalservice.api.util.CredentialsProvider;
import org.whispersystems.signalservice.api.util.SleepTimer;
import org.whispersystems.signalservice.api.util.UptimeSleepTimer;
import org.whispersystems.signalservice.api.websocket.WebSocketFactory;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;
import org.whispersystems.signalservice.internal.websocket.WebSocketConnection;

public class SignalDependencies {
  SignalWebSocket websocket;
  SignalServiceConfiguration serviceConfiguration;
  SignalServiceDataStore dataStore;
  DynamicCredentialsProvider credentialsProvider;

  public SignalDependencies(UUID uuid, SignalServiceConfiguration signalServiceConfiguration, CredentialsProvider credentialsProvider) {
    final SleepTimer timer = new UptimeSleepTimer();
    SignalWebSocketHealthMonitor healthMonitor = new SignalWebSocketHealthMonitor(timer);
    final WebSocketFactory webSocketFactory = new WebSocketFactory() {
      @Override
      public WebSocketConnection createWebSocket() {
        return new WebSocketConnection("normal", signalServiceConfiguration, Optional.of(credentialsProvider), BuildConfig.USER_AGENT, healthMonitor);
      }

      @Override
      public WebSocketConnection createUnidentifiedWebSocket() {
        return new WebSocketConnection("unidentified", signalServiceConfiguration, Optional.absent(), BuildConfig.USER_AGENT, healthMonitor);
      }
    };
    websocket = new SignalWebSocket(webSocketFactory);
  }

  public SignalWebSocket getWebsocket() { return websocket; }
}
