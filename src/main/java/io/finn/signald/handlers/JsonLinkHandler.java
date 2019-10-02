package io.finn.signald.handlers;

import io.finn.signald.*;
import org.asamk.signal.UserAlreadyExists;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

public class JsonLinkHandler extends BaseJsonHandler {
  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager();
    m.createNewIdentity();
    String deviceName = "signald"; // TODO: Set this to "signald on <hostname>"
    if (request.deviceName != null) {
      deviceName = request.deviceName;
    }
    try {
      m.getDeviceLinkUri();
      return new JsonMessageWrapper("linking_uri", new JsonLinkingURI(m), request.id);
      // TODO LIG: Make method asynchronous
      m.finishDeviceLink(deviceName);
      ManagerFactory.putManager(m);
      return new JsonMessageWrapper("linking_successful", new JsonAccount(m), request.id);
    } catch (TimeoutException e) {
      return new JsonMessageWrapper("linking_error", new JsonStatusMessage(1, "Timed out while waiting for device to link", request), request.id);
    } catch (IOException e) {
      return new JsonMessageWrapper("linking_error", new JsonStatusMessage(2, e.getMessage(), request), request.id);
    } catch (UserAlreadyExists e) {
      return new JsonMessageWrapper("linking_error", new JsonStatusMessage(3, "The user " + e.getUsername() + " already exists. Delete \"" + e.getFileName() + "\" and trying again.", request), request.id);
    }

  }
}
