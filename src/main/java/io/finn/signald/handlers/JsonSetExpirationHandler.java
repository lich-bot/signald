package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.Manager;
import io.finn.signald.ManagerFactory;
import org.asamk.signal.AttachmentInvalidException;
import org.asamk.signal.GroupNotFoundException;
import org.asamk.signal.NotAGroupMemberException;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.push.exceptions.EncapsulatedExceptions;
import org.whispersystems.signalservice.internal.util.Base64;

import java.io.IOException;

public class JsonSetExpirationHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);

    try {
      if (request.recipientGroupId != null) {
        byte[] groupId = Base64.decode(request.recipientGroupId);
        m.setExpiration(groupId, request.expiresInSeconds);
      } else {
        m.setExpiration(request.recipientNumber, request.expiresInSeconds);
      }
    } catch (GroupNotFoundException |
        NotAGroupMemberException |
        AttachmentInvalidException |
        EncapsulatedExceptions |
        UntrustedIdentityException e) {
      return wrapException(e, "set_error", request);
    }

    return new JsonMessageWrapper("expiration_updated", null, request.id);
  }
}
