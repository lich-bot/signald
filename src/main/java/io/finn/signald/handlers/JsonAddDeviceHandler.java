package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;
import java.net.URI;

public class JsonAddDeviceHandler extends BaseJsonHandler {
  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    m.addDeviceLink(new URI(request.uri));
    return new JsonMessageWrapper("device_added",
        new JsonStatusMessage(4, "Successfully linked device"),
        request.id
    );
  }
}
