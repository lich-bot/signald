package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonVerifyHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    if (!m.userHasKeys()) {
      String message = "User has no keys, first call register.";
      logger.warn(message);
      return new JsonMessageWrapper("user_not_registered",
          new JsonStatusMessage(0, message, request)
      );
    } else if (m.isRegistered()) {
      String message = "User is already verified";
      logger.warn(message);
      // TODO code-review: Is this correct?
      return new JsonMessageWrapper("user_already_verified",
          new JsonStatusMessage(0, message, request)
      );
    } else {
      logger.info("Submitting verification code " + request.code + " for number " + request.username);
      m.verifyAccount(request.code);
      return new JsonMessageWrapper("verification_succeeded", new JsonAccount(m), request.id);
    }
  }
}
