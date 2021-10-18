/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import io.finn.signald.Account;
import io.finn.signald.annotations.AtLeastOneOfRequired;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.annotations.ProtocolType;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.*;
import io.finn.signald.clientprotocol.v2alpha1.exceptions.InternalError;
import io.finn.signald.db.Recipient;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import org.whispersystems.signalservice.api.messages.SendMessageResult;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;

@ProtocolType("send_message")
public class SendMessageRequest implements RequestType<MessageDeliveryResults> {

  @ExampleValue(ExampleValue.LOCAL_UUID) public String account;
  @Doc("the conversation to send the message to") public Conversation conversation;
  @Doc("the text of the message to send") @ExampleValue(ExampleValue.MESSAGE_BODY) @AtLeastOneOfRequired({"attachments"}) public String body;
  @AtLeastOneOfRequired({"body"}) public List<Attachment> attachments;
  //	public JsonQuote quote;
  public Long timestamp;
  //	public List<JsonMention> mentions;
  //	public List<JsonPreview> previews;

  @Override
  public MessageDeliveryResults run(Request request) throws InternalError, ServerNotFoundError, InvalidProxyError, NoSuchAccountError, InvalidRecipientError, UnknownGroupError,
                                                            NoSendPermissionError, InvalidRequestError, StreamNotReadyError {
    Account a = Common.getAccount(account);
    Recipient recipient = null;
    if (conversation.user != null) {
      try {
        recipient = a.getRecipients().get(UUID.fromString(conversation.user));
      } catch (IOException | SQLException e) {
        throw new InternalError("error looking up recipient", e);
      }
    }

    SignalServiceDataMessage.Builder messageBuilder = SignalServiceDataMessage.newBuilder();

    if (body != null) {
      messageBuilder.withBody(body);
    }

    if (attachments != null) {
      for (Attachment attachment : attachments) {
        messageBuilder.withAttachment(attachment.getSignalServiceAttachment());
      }
    }

    if (timestamp == null) {
      timestamp = System.currentTimeMillis();
    }
    messageBuilder.withTimestamp(timestamp);

    List<SendMessageResult> results;
    results = Common.send(Common.getManager(account), messageBuilder, recipient, conversation.groupId);

    return new MessageDeliveryResults(results, timestamp);
  }
}
