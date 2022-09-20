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
import java.util.List;
import java.util.stream.Collectors;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;

@ProtocolType("send_ice_updates")
public class SendIceUpdatesRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("the local account to use") @Required public String account;

  @Required @Doc("the address of the caller") public JsonAddress recipient;

  @Required public List<IceUpdateMessage> updates;

  public boolean multiring;

  @JsonProperty("destination_device_id") public Integer destinationDeviceId;

  @Override
  public Empty run(Request request)
      throws NoSuchAccountError, SQLError, InternalError, UnregisteredUserError, AuthorizationFailedError, ServerNotFoundError, InvalidProxyError, UntrustedIdentityError {
    List<org.whispersystems.signalservice.api.messages.calls.IceUpdateMessage> iceUpdates = updates.stream().map(IceUpdateMessage::getProtocolMessage).collect(Collectors.toList());
    Account a = Common.getAccount(account);
    Recipient r = Common.getRecipient(a.getDB().RecipientsTable, recipient);

    Common.sendCallMessage(a, r, SignalServiceCallMessage.forIceUpdates(iceUpdates, multiring, destinationDeviceId));

    return new Empty();
  }
}
