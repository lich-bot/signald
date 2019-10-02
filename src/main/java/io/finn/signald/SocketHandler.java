/**
 * Copyright (C) 2018 Finn Herzfeld
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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.finn.signald.handlers.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SocketHandler implements Runnable {
  private BufferedReader reader;
  private PrintWriter writer;
  private ConcurrentHashMap<String, MessageReceiver> receivers;
  private ConcurrentHashMap<String, BaseJsonHandler> handlers;
  private ObjectMapper mpr = new ObjectMapper();
  private static final Logger logger = LogManager.getLogger();
  private Socket socket;
  private ArrayList<String> subscribedAccounts = new ArrayList<String>();
  private String data_path;

  public SocketHandler(Socket socket, ConcurrentHashMap<String, MessageReceiver> receivers, ConcurrentHashMap<String, Manager> managers, String data_path) throws IOException {
    this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    this.writer = new PrintWriter(socket.getOutputStream(), true);
    this.socket = socket;
    this.receivers = receivers;
    this.data_path = data_path;

    this.mpr.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY); // disable autodetect
    this.mpr.setSerializationInclusion(Include.NON_NULL);
    this.mpr.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    this.mpr.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
    handlers = new ConcurrentHashMap<String, BaseJsonHandler>() {{
      put("add_device", new JsonAddDeviceHandler());
      put("get_identities", new JsonGetIdentitiesHandler());
      put("get_user", new JsonGetUserHandler());
      put("leave_group", new JsonLeaveGroupHandler());
      put("link", new JsonLinkHandler());
      put("list_accounts", new JsonListAccountsHandler(subscribedAccounts));
      put("list_groups", new JsonListGroupsHandler());
      put("list_contacts", new JsonListContactsHandler());
      put("register", new JsonRegisterHandler());
      put("send", new JsonSendHandler());
      put("set_expiration", new JsonSetExpirationHandler());
      put("subscribe", new JsonSubscribeHandler(receivers, subscribedAccounts, socket));
      put("sync_contacts", new JsonSyncContactsHandler());
      put("unsubscribe", new JsonUnsubscribeHandler(receivers, subscribedAccounts, socket));
      put("update_group", new JsonUpdateGroupHandler());
      put("update_contact", new JsonUpdateContactHandler());
      put("verify", new JsonVerifyHandler());
      put("trust", new JsonTrustHandler());
      put("version", new JsonVersionHandler());
    }};
  }

  @Override
  public void run() {
    logger.info("Client connected");

    try {
      this.reply("version", new JsonVersionMessage(), null);
    } catch (JsonProcessingException e) {
      handleError(e, null);
    }

    while (true) {
      String line = null;
      JsonRequest request;
      try {
        line = this.reader.readLine();
        if (line == null) {
          logger.info("Client disconnected");
          this.reader.close();
          this.writer.close();
          for (Map.Entry<String, MessageReceiver> entry : this.receivers.entrySet()) {
            if (entry.getValue().unsubscribe(this.socket)) {
              logger.info("Unsubscribed from " + entry.getKey());
            }
          }
          return;
        }
        if (!line.equals("")) {
          logger.debug(line);
          request = this.mpr.readValue(line, JsonRequest.class);
          try {
            handleRequest(request);
          } catch (Throwable e) {
            handleError(e, request);
          }
        }
      } catch (IOException e) {
        handleError(e, null);
        break;
      }
    }
  }

  private void handleRequest(JsonRequest request) throws Throwable {
    BaseJsonHandler handler = this.handlers.get(request.type);
    if (handler == null) {
      logger.warn("Unknown command type " + request.type);
      this.reply("unknown_command", new JsonStatusMessage(5, "Unknown command type " + request.type, request), request.id);

    } else {
      this.reply(handler.handle(request));
    }
  }

  private void reply(JsonMessageWrapper message) throws JsonProcessingException {
    String jsonmessage = this.mpr.writeValueAsString(message);
    PrintWriter out = new PrintWriter(this.writer, true);
    out.println(jsonmessage);
  }

  private void reply(String type, Object data, String id) throws JsonProcessingException {
    this.reply(new JsonMessageWrapper(type, data, id));
  }

  private void handleError(Throwable error, JsonRequest request) {
    logger.catching(error);
    String requestid = "";
    if (request != null) {
      requestid = request.id;
    }
    try {
      this.reply("unexpected_error", new JsonStatusMessage(0, error.getMessage(), request), requestid);
    } catch (JsonProcessingException e) {
      logger.catching(error);
    }
  }
}
