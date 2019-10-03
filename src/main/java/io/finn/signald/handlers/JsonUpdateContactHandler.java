package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonUpdateContactHandler extends BaseJsonHandler {
  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    if (request.contact == null) {
      return new JsonMessageWrapper("update_contact_error", new JsonStatusMessage(0, "No contact specificed!", request), request.id);

    }

    if (request.contact.number == null) {
      return new JsonMessageWrapper("update_contact_error", new JsonStatusMessage(0, "No number specified! Contact must have a number", request), request.id);
    }

    m.updateContact(request.contact);
    return new JsonMessageWrapper("contact_updated", null, request.id);
  }
}
