package io.finn.signald.handlers;

import io.finn.signald.*;
import org.asamk.signal.GroupNotFoundException;
import org.asamk.signal.NotAGroupMemberException;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.push.exceptions.EncapsulatedExceptions;
import org.whispersystems.signalservice.internal.util.Base64;

import java.io.IOException;

public class JsonLeaveGroupHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    byte[] groupId = Base64.decode(request.recipientGroupId);
    try {
      m.sendQuitGroupMessage(groupId);
    } catch (GroupNotFoundException |
        EncapsulatedExceptions |
        UntrustedIdentityException |
        NotAGroupMemberException e) {
      return this.wrapException(e, "leave_group_error", request);
    }
    return new JsonMessageWrapper("left_group",
        new JsonStatusMessage(7, "Successfully left group"),
        request.id
    );
  }
}
