package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.MessageReceiver;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class JsonSubscribeHandler extends BaseJsonHandler {

    private ConcurrentHashMap<String, MessageReceiver> receivers;
    private ArrayList<String> subscribedAccounts;
    private Socket socket;

    public JsonSubscribeHandler(
            ConcurrentHashMap<String, MessageReceiver> receivers,
            ArrayList<String> subscribedAccounts,
            Socket socket
    ) {
        this.receivers = receivers;
        this.subscribedAccounts = subscribedAccounts;
        this.socket = socket;
    }

    @Override
    public JsonMessageWrapper handle(JsonRequest request) throws IOException {
        if (!this.receivers.containsKey(request.username)) {
            MessageReceiver receiver = new MessageReceiver(request.username);
            this.receivers.put(request.username, receiver);
            Thread messageReceiverThread = new Thread(receiver);
            messageReceiverThread.start();
        }
        this.receivers.get(request.username).subscribe(this.socket);
        this.subscribedAccounts.add(request.username);
        // TODO: Indicate if we actually subscribed or were already subscribed,
        //  also which username it was for
        return new JsonMessageWrapper("subscribed", null, request.id);

    }
}
