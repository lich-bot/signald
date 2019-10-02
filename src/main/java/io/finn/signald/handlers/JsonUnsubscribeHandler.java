package io.finn.signald.handlers;

import io.finn.signald.JsonMessageWrapper;
import io.finn.signald.JsonRequest;
import io.finn.signald.MessageReceiver;

import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class JsonUnsubscribeHandler extends BaseJsonHandler {

    private ConcurrentHashMap<String, MessageReceiver> receivers;
    private ArrayList<String> subscribedAccounts = new ArrayList<String>();
    private Socket socket;

    public JsonUnsubscribeHandler(
            ConcurrentHashMap<String, MessageReceiver> receivers,
            ArrayList<String> subscribedAccounts,
            Socket socket
    ) {
        this.receivers = receivers;
        this.subscribedAccounts = subscribedAccounts;
        this.socket = socket;
    }

    @Override
    public JsonMessageWrapper handle(JsonRequest request) {
        this.receivers.get(request.username).unsubscribe(this.socket);
        this.subscribedAccounts.remove(request.username);
        // TODO: Indicate if we actually unsubscribed or were already unsubscribed,
        //  also which username it was for
        return new JsonMessageWrapper("unsubscribed", null, request.id);
    }
}
