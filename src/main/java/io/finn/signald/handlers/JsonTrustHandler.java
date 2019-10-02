package io.finn.signald.handlers;

import io.finn.signald.*;
import org.asamk.signal.util.Hex;

import java.io.IOException;
import java.util.Locale;

public class JsonTrustHandler extends BaseJsonHandler {

  @Override
  public JsonMessageWrapper handle(JsonRequest request) throws IOException {
    Manager m = ManagerFactory.getManager(request.username);
    String fingerprint = request.fingerprint.replaceAll(" ", "");
    JsonMessageWrapper messageWrapper = null;
    if (fingerprint.length() == 66) {
      byte[] fingerprintBytes;
      fingerprintBytes = Hex.toByteArray(fingerprint.toLowerCase(Locale.ROOT));
      boolean res = m.trustIdentityVerified(request.recipientNumber, fingerprintBytes);
      if (!res) {
        messageWrapper = new JsonMessageWrapper("trust_failed", new JsonStatusMessage(0, "Failed to set the trust for the fingerprint of this number, make sure the number and the fingerprint are correct.", request), request.id);
      } else {
        messageWrapper = new JsonMessageWrapper("trusted_fingerprint", new JsonStatusMessage(0, "Successfully trusted fingerprint", request), request.id);
      }
    } else if (fingerprint.length() == 60) {
      boolean res = m.trustIdentityVerifiedSafetyNumber(request.recipientNumber, fingerprint);
      if (!res) {
        messageWrapper = new JsonMessageWrapper("trust_failed", new JsonStatusMessage(0, "Failed to set the trust for the safety number of this number, make sure the number and the safety number are correct.", request), request.id);
      } else {
        messageWrapper = new JsonMessageWrapper("trusted_safety_number", new JsonStatusMessage(0, "Successfully trusted safety number", request), request.id);
      }
    } else {
      System.err.println("Fingerprint has invalid format, either specify the old hex fingerprint or the new safety number");
      messageWrapper = new JsonMessageWrapper("trust_failed", new JsonStatusMessage(0, "Fingerprint has invalid format, either specify the old hex fingerprint or the new safety number", request), request.id);
    }
    return messageWrapper;
  }

}
