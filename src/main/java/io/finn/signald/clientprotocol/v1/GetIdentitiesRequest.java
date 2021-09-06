/*
 * Copyright (C) 2021 Finn Herzfeld
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.finn.signald.clientprotocol.v1;

import io.finn.signald.Manager;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;
import io.finn.signald.annotations.ProtocolType;
import io.finn.signald.annotations.Required;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.InvalidProxyException;
import io.finn.signald.clientprotocol.v1.exceptions.NoSuchAccount;
import io.finn.signald.clientprotocol.v1.exceptions.ServerNotFoundException;
import io.finn.signald.db.IdentityKeysTable;
import io.finn.signald.db.Recipient;
import io.finn.signald.exceptions.InvalidAddressException;
import io.finn.signald.exceptions.NoSuchAccountException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import org.whispersystems.libsignal.InvalidKeyException;

@Doc("Get information about a known keys for a particular address")
@ProtocolType("get_identities")
public class GetIdentitiesRequest implements RequestType<IdentityKeyList> {
  @ExampleValue(ExampleValue.LOCAL_PHONE_NUMBER) @Doc("The account to interact with") @Required public String account;

  @Doc("address to get keys for") @Required public JsonAddress address;

  @Override
  public IdentityKeyList run(Request request)
      throws SQLException, IOException, NoSuchAccount, InvalidAddressException, InvalidKeyException, ServerNotFoundException, InvalidProxyException, NoSuchAccountException {
    Manager m = Utils.getManager(account);
    Recipient recipient = m.getRecipientsTable().get(address);
    List<IdentityKeysTable.IdentityKeyRow> identities = m.getIdentities(recipient);
    return new IdentityKeyList(m.getOwnRecipient(), m.getIdentity(), recipient, identities);
  }
}
