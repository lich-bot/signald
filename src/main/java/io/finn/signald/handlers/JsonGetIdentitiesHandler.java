package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonGetIdentitiesHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    return new JsonMessageWrapper("identities",
        new JsonIdentityList(request.recipientNumber, m),
        request.id
    );
  }

}
