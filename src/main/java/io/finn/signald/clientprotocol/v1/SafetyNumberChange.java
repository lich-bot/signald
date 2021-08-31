package io.finn.signald.clientprotocol.v1;

import io.finn.signald.annotations.ExampleValue;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public class SafetyNumberChange {
    @ExampleValue("+12345678901")
    public String identifier;

    public SafetyNumberChange(String identifier) {
        this.identifier = identifier;
    }
}
