package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.JsonStatusMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public abstract class BaseJsonHandler {
  static final Logger logger = LogManager.getLogger();

  JsonMessageWrapper wrapException(Throwable e, String wrapperType) {
    return wrapException(e, wrapperType, null);
  }

  JsonMessageWrapper wrapException(Throwable e, String wrapperType, JsonRequest request) {
    return new JsonMessageWrapper(wrapperType, new JsonStatusMessage(0, e.getMessage(), request));
  }

  public abstract JsonMessageWrapper handle(JsonRequest request) throws IOException;
}
