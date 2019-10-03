package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonListContactsHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    return new JsonMessageWrapper("contact_list", m.getContacts(), request.id);
  }

}
