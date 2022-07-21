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
import org.whispersystems.signalservice.api.messages.calls.AnswerMessage;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos;

@ProtocolType("answer_call")
public class AnswerCallRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("the local account to use") @Required public String account;

  @Required @Doc("the address of the caller") public JsonAddress recipient;

  @Required @Doc("the id of the call") @JsonProperty("call_id") public long id;

  public String sdp;

  public boolean multiring;

  @JsonProperty("destination_device_id") public Integer destinationDeviceId;

  @Override
  public Empty run(Request request)
      throws NoSuchAccountError, SQLError, InternalError, ServerNotFoundError, InvalidProxyError, UnregisteredUserError, AuthorizationFailedError, UntrustedIdentityError {
    SignalServiceProtos.CallMessage.Answer.Builder builder = SignalServiceProtos.CallMessage.Answer.newBuilder();
    builder.setId(id);
    if (sdp != null) {
      builder.setSdp(sdp);
    }

    AnswerMessage answer = new AnswerMessage(id, sdp, builder.build().toByteArray());

    Account a = Common.getAccount(account);
    Recipient r = Common.getRecipient(a.getDB().RecipientsTable, recipient);

    Common.sendCallMessage(a, r, SignalServiceCallMessage.forAnswer(answer, multiring, destinationDeviceId));

    return new Empty();
  }
}
