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

import io.finn.signald.db.DatabaseProtocolStore;
import io.finn.signald.db.ServersTable;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.signal.zkgroup.profiles.ClientZkProfileOperations;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceDataStore;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.SignalWebSocket;
import org.whispersystems.signalservice.api.groupsv2.ClientZkOperations;
import org.whispersystems.signalservice.api.util.SleepTimer;
import org.whispersystems.signalservice.api.util.UptimeSleepTimer;
import org.whispersystems.signalservice.api.websocket.WebSocketFactory;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;
import org.whispersystems.signalservice.internal.websocket.WebSocketConnection;

public class SignalDependencies {
  private final SignalServiceConfiguration serviceConfiguration;
  private final SignalServiceDataStore dataStore;
  private final DynamicCredentialsProvider credentialsProvider;
  private final SessionLock sessionLock;
  private final ExecutorService executor = Executors.newCachedThreadPool();

  private SignalWebSocket websocket;
  private final Object websocketLock = new Object();

  private SignalServiceMessageReceiver messageReceiver;
  private final Object messageReceiverLock = new Object();

  private SignalServiceMessageSender messageSender;
  private final Object messageSenderLock = new Object();

  public SignalDependencies(UUID account, ServersTable.Server server, DynamicCredentialsProvider credentialsProvider) {
    dataStore = new DatabaseProtocolStore(account);
    serviceConfiguration = server.getSignalServiceConfiguration();
    this.credentialsProvider = credentialsProvider;

    final SleepTimer timer = new UptimeSleepTimer();
    SignalWebSocketHealthMonitor healthMonitor = new SignalWebSocketHealthMonitor(timer);
    final WebSocketFactory webSocketFactory = new WebSocketFactory() {
      @Override
      public WebSocketConnection createWebSocket() {
        return new WebSocketConnection("normal", serviceConfiguration, Optional.of(credentialsProvider), BuildConfig.USER_AGENT, healthMonitor);
      }

      @Override
      public WebSocketConnection createUnidentifiedWebSocket() {
        return new WebSocketConnection("unidentified", serviceConfiguration, Optional.absent(), BuildConfig.USER_AGENT, healthMonitor);
      }
    };
    websocket = new SignalWebSocket(webSocketFactory);
    sessionLock = new SessionLock(account);
  }

  public SignalWebSocket getWebSocket() {
    synchronized (websocketLock) {
      if (websocket != null) {
        UptimeSleepTimer timer = new UptimeSleepTimer();
        SignalWebSocketHealthMonitor healthMonitor = new SignalWebSocketHealthMonitor(timer);
        WebSocketFactory webSocketFactory = new WebSocketFactory() {
          @Override
          public WebSocketConnection createWebSocket() {
            return new WebSocketConnection("normal", serviceConfiguration, Optional.of(credentialsProvider), BuildConfig.USER_AGENT, healthMonitor);
          }

          @Override
          public WebSocketConnection createUnidentifiedWebSocket() {
            return new WebSocketConnection("unidentified", serviceConfiguration, Optional.absent(), BuildConfig.USER_AGENT, healthMonitor);
          }
        };
        websocket = new SignalWebSocket(webSocketFactory);
        healthMonitor.monitor(websocket);
      }
    }
    return websocket;
  }

  public SignalServiceMessageReceiver getMessageReceiver() {
    synchronized (messageReceiverLock) {
      if (messageReceiver == null) {
        ClientZkProfileOperations profileOperations = ClientZkOperations.create(serviceConfiguration).getProfileOperations();
        messageReceiver =
            new SignalServiceMessageReceiver(serviceConfiguration, credentialsProvider, BuildConfig.USER_AGENT, profileOperations, ServiceConfig.AUTOMATIC_NETWORK_RETRY);
      }
    }
    return messageReceiver;
  }

  public SignalServiceMessageSender getMessageSender() {
    synchronized (messageSenderLock) {
      if (messageSender == null) {
        ClientZkProfileOperations profileOperations = ClientZkOperations.create(serviceConfiguration).getProfileOperations();
        messageSender = new SignalServiceMessageSender(serviceConfiguration, credentialsProvider, dataStore, sessionLock, BuildConfig.USER_AGENT, getWebSocket(), Optional.absent(),
                                                       profileOperations, executor, ServiceConfig.MAX_ENVELOPE_SIZE, ServiceConfig.AUTOMATIC_NETWORK_RETRY);
      }
    }
    return messageSender;
  }

  public void shutdown() { executor.shutdown(); }
}
