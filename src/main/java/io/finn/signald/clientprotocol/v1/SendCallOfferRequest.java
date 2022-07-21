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
import org.whispersystems.signalservice.api.messages.calls.OfferMessage;
import org.whispersystems.signalservice.api.messages.calls.SignalServiceCallMessage;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos;

@ProtocolType("send_call_offer")
public class SendCallOfferRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("the local account to use") @Required public String account;

  @Required @Doc("the address of the caller") public JsonAddress recipient;

  @Required @Doc("the id of the call") @JsonProperty("call_id") public long id;

  public String sdp;

  @Required @Doc("must be one of 'audio_call' or 'video_call'") @JsonProperty("call_type") public String type;

  public boolean multring;

  @JsonProperty("destination_device_id") public Integer destinationDeviceId;

  @Override
  public Empty run(Request request) throws NoSuchAccountError, SQLError, InternalError, ServerNotFoundError, InvalidProxyError, UnregisteredUserError, AuthorizationFailedError,
                                           UntrustedIdentityError, InvalidRequestError {
    SignalServiceProtos.CallMessage.Offer.Builder builder = SignalServiceProtos.CallMessage.Offer.newBuilder();
    builder.setId(id);
    if (sdp != null) {
      builder.setSdp(sdp);
    }
    switch (type) {
    case "audio_call":
      builder.setType(SignalServiceProtos.CallMessage.Offer.Type.OFFER_AUDIO_CALL);
      break;
    case "video_call":
      builder.setType(SignalServiceProtos.CallMessage.Offer.Type.OFFER_VIDEO_CALL);
      break;
    default:
      throw new InvalidRequestError("type must be one of 'audio_call' or 'video_call'");
    }

    OfferMessage.Type offerType = builder.getType() == SignalServiceProtos.CallMessage.Offer.Type.OFFER_AUDIO_CALL ? OfferMessage.Type.AUDIO_CALL : OfferMessage.Type.VIDEO_CALL;
    OfferMessage offer = new OfferMessage(id, sdp, offerType, builder.build().toByteArray());

    Account a = Common.getAccount(account);
    Recipient r = Common.getRecipient(a.getDB().RecipientsTable, recipient);

    Common.sendCallMessage(a, r, SignalServiceCallMessage.forOffer(offer, multring, destinationDeviceId));

    return new Empty();
  }
}
