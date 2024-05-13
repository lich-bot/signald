package io.finn.signald.db;

import io.finn.signald.Account;
import io.finn.signald.SignalDependencies;
import io.finn.signald.clientprotocol.v1.JsonAddress;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.ServiceId.ACI;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.services.CdsiV2Service;

public interface IRecipientsTable {
  Logger logger = LogManager.getLogger();

  String ROW_ID = "rowid";
  String ACCOUNT_UUID = "account_uuid";
  String UUID = "uuid";
  String E164 = "e164";
  String REGISTERED = "registered";
  String NEEDS_PNI_SIGNATURE = "needs_pni_signature";

  Recipient get(String e164, ServiceId aci) throws SQLException, IOException;
  Recipient self() throws SQLException, IOException;
  void setRegistrationStatus(Recipient recipient, boolean registered) throws SQLException, IOException;
  void deleteAccount(ACI aci) throws SQLException;

  public Map<ServiceId, ProfileKey> getServiceIdToProfileKeyMap() throws SQLException;

  default List<Recipient> get(List<SignalServiceAddress> addresses) throws SQLException, IOException {
    List<Recipient> results = new ArrayList<>();
    for (SignalServiceAddress address : addresses) {
      results.add(get(address));
    }
    return results;
  }

  default Recipient get(SignalServiceAddress address) throws SQLException, IOException { return get(address.getNumber().orElse(null), address.getServiceId()); }

  default Recipient get(JsonAddress address) throws IOException, SQLException { return get(address.number, address.getACI()); }

  default Recipient get(UUID query) throws IOException, SQLException { return get(ACI.from(query)); }

  default Recipient get(ServiceId query) throws SQLException, IOException { return get(null, query); };

  default Recipient get(String identifier) throws IOException, SQLException {
    if (identifier.startsWith("+")) {
      return get(identifier, null);
    } else {
      return get(null, ACI.from(java.util.UUID.fromString(identifier)));
    }
  }

  default Map<String, ACI> getRegisteredUsers(Account account, final Set<String> numbers)
      throws IOException, InvalidProxyException, SQLException, ServerNotFoundException, NoSuchAccountException {
    Set<String> previousNumbers = Set.of(); // TODO

    SignalServiceAccountManager accountManager = account.getSignalDependencies().getAccountManager();

    Optional<byte[]> token = previousNumbers.isEmpty() ? Optional.empty() : account.getCdsiToken();

    logger.debug("querying server for UUIDs of " + numbers.size() + " e164 identifiers");
    CdsiV2Service.Response response =
        accountManager.getRegisteredUsersWithCdsi(Set.of(), numbers, getServiceIdToProfileKeyMap(), true, token, account.getCdsMrenclave(), null, null);
    logger.error("GET REGISTERED USERS NOT YET IMPLEMENTED");

    throw new RuntimeException("registered users not yet implemented");

    //    return new HashMap<>();
  }
}
