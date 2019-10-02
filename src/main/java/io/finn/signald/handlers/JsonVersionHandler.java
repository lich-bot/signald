package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.JsonVersionMessage;

import java.io.IOException;

public class JsonVersionHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    return new JsonMessageWrapper("version", new JsonVersionMessage());
  }
}
