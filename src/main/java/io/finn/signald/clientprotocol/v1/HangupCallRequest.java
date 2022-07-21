package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.Account;
import io.finn.signald.Empty;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.annotations.ProtocolType;
import io.finn.signald.annotations.Required;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;
import io.finn.signald.db.Recipient;
import org.whispersystems.signalservice.api.messages.calls.HangupMessage;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;

@ProtocolType("hangup_call")
public class HangupCallRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("the local account to use") @Required public String account;

  @Required @Doc("the address of the caller") public JsonAddress recipient;

  @Required @Doc("the id of the call") @JsonProperty("call_id") public long id;

  @JsonProperty("device_id") public Integer deviceId;

  @Doc("hangup type, options are: normal, accepted, declined, busy, need_permission") public String type;

  public boolean multiring;

  @JsonProperty("destination_device_id") public Integer destinationDeviceId;

  @Override
  public Empty run(Request request) throws NoSuchAccountError, SQLError, InternalError, UnregisteredUserError, AuthorizationFailedError, ServerNotFoundError, InvalidProxyError,
                                           UntrustedIdentityError, InvalidRequestError {
    HangupMessage.Type hangupType;
    switch (type) {
    case "normal":
      hangupType = HangupMessage.Type.NORMAL;
      break;
    case "accepted":
      hangupType = HangupMessage.Type.ACCEPTED;
      break;
    case "declined":
      hangupType = HangupMessage.Type.DECLINED;
      break;
    case "busy":
      hangupType = HangupMessage.Type.BUSY;
      break;
    case "need_permission":
      hangupType = HangupMessage.Type.NEED_PERMISSION;
      break;
    default:
      throw new InvalidRequestError("unknown hangup type. Valid types are normal, accepted, declined, busy, need_permission");
    }

    org.whispersystems.signalservice.api.messages.calls.HangupMessage hangup = new HangupMessage(id, hangupType, deviceId, false);

    Account a = Common.getAccount(account);
    Recipient r = Common.getRecipient(a.getDB().RecipientsTable, recipient);

    Common.sendCallMessage(a, r, SignalServiceCallMessage.forHangup(hangup, multiring, destinationDeviceId));

    return new Empty();
  }
}
