package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.Manager;
import io.finn.signald.ManagerFactory;

import java.io.IOException;

public class JsonSyncContactsHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    m.requestSyncContacts();
    return new JsonMessageWrapper("sync_requested", null, request.id);
  }
}
