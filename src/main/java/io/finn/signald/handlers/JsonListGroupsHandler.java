package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonListGroupsHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    return new JsonMessageWrapper("group_list", new JsonGroupList(m), request.id);
  }
}
