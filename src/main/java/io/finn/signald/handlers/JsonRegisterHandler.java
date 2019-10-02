package io.finn.signald.handlers;

import io.finn.signald.*;

import java.io.IOException;

public class JsonRegisterHandler extends BaseJsonHandler {

    public JsonRegisterHandler() {
    }

    @Override
    public JsonMessageWrapper handle(JsonRequest request) throws IOException {
        logger.info("Register request: " + request);
        Manager m = ManagerFactory.getManager(request.username);
        Boolean voice = false;
        if (request.voice != null) {
            voice = request.voice;
        }

        if (!m.userHasKeys()) {
            logger.info("User has no keys, making some");
            m.createNewIdentity();
        }
        logger.info("Registering (voice: " + voice + ")");
        m.register(voice);
        return new JsonMessageWrapper("verification_required", new JsonAccount(m), request.id);
    }
}
