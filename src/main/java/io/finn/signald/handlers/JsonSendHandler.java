package io.finn.signald.handlers;

import io.finn.signald.*;
import org.asamk.signal.AttachmentInvalidException;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachmentStream;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.internal.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class JsonSendHandler extends BaseJsonHandler {
    @Override
    public JsonMessageWrapper handle(JsonRequest request) throws Exception {
        Manager manager = ManagerFactory.getManager(request.username);

        SignalServiceDataMessage.Quote quote = null;

        if (request.quote != null) {
            quote = request.quote.getQuote();
        }

        if (request.attachmentFilenames != null) {
            logger.warn("Using deprecated attachmentFilenames argument for send! Use attachments instead");
            if (request.attachments == null) {
                request.attachments = new ArrayList<JsonAttachment>();
            }
            for (String attachmentFilename : request.attachmentFilenames) {
                request.attachments.add(new JsonAttachment(attachmentFilename));
            }
        }

        List<SignalServiceAttachment> attachments = null;
        if (request.attachments != null) {
            attachments = new ArrayList<>(request.attachments.size());
            for (JsonAttachment attachment : request.attachments) {
                try {
                    File attachmentFile = new File(attachment.filename);
                    InputStream attachmentStream = new FileInputStream(attachmentFile);
                    final long attachmentSize = attachmentFile.length();
                    String mime = Files.probeContentType(attachmentFile.toPath());
                    if (mime == null) {
                        mime = "application/octet-stream";
                    }

                    attachments.add(new SignalServiceAttachmentStream(attachmentStream, mime, attachmentSize, Optional.of(attachmentFile.getName()), attachment.voiceNote, attachment.getPreview(), attachment.width, attachment.height, Optional.fromNullable(attachment.caption), null));
                } catch (IOException e) {
                    throw new AttachmentInvalidException(attachment.filename, e);
                }
            }
        }

        if (request.recipientGroupId != null) {
            byte[] groupId = Base64.decode(request.recipientGroupId);
            manager.sendGroupMessage(request.messageBody, attachments, groupId, quote);
        } else {
            manager.sendMessage(request.messageBody, attachments, request.recipientNumber, quote);
        }
        return new JsonMessageWrapper("success", new JsonStatusMessage(0, "success"), request.id);

    }
}
