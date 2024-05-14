package io.finn.signald.db;

import io.finn.signald.Account;
import io.finn.signald.ServiceConfig;
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

  Map<ServiceId, ProfileKey> getServiceIdToProfileKeyMap() throws SQLException;

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

  default Map<String, ACI> getRegisteredUsers(Account account, final Set<String> queryNumbers)
      throws IOException, InvalidProxyException, SQLException, ServerNotFoundException, NoSuchAccountException {
    ICdsiTable cdsiTable = account.getDB().CdsiTable;

    boolean isPartialRefresh = queryNumbers.size() < ServiceConfig.CDSI_MAXIMUM_ONE_OFF_REQUEST_SIZE;
    Set<String> previousNumbers = isPartialRefresh ? Set.of() : cdsiTable.allNumbers();

    Optional<byte[]> token = previousNumbers.isEmpty() ? Optional.empty() : account.getCdsiToken();

    logger.debug("querying server for ACIs of " + queryNumbers.size() + " e164 identifiers");
    SignalServiceAccountManager accountManager = account.getSignalDependencies().getAccountManager();
    CdsiV2Service.Response response = accountManager.getRegisteredUsersWithCdsi(previousNumbers,               // previousE164s
                                                                                queryNumbers,                  // newE164s
                                                                                getServiceIdToProfileKeyMap(), // serviceIds
                                                                                true,                          // requireAcis
                                                                                token,                         // token
                                                                                account.getCdsMrenclave(),     // mrEnclave
                                                                                null,                          // timeout
                                                                                account.getTokenSaver()        // tokenSaver
    );

    logger.debug("CDS query succeeded, {} quota remaining", response.getQuotaUsedDebugOnly());

    HashMap<String, ACI> result = new HashMap<>();
    for (Map.Entry<String, CdsiV2Service.ResponseItem> responseEntry : response.getResults().entrySet()) {
      if (responseEntry.getValue().getAci().isPresent()) {
        result.put(responseEntry.getKey(), responseEntry.getValue().getAci().get());
      }
    }

    return result;
  }
}
