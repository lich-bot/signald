package io.finn.signald.db;

import java.sql.SQLException;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;

public interface ISignedPreKeysTable extends SignedPreKeyStore {
  String ACCOUNT_UUID = "account_uuid";
  String ID = "id";
  String RECORD = "record";

  void deleteAccount(ACI aci) throws SQLException;
}
