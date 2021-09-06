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

import io.finn.signald.Empty;
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
import io.finn.signald.exceptions.NoSuchAccountException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.SQLException;
import org.signal.zkgroup.InvalidInputException;
import org.whispersystems.libsignal.InvalidKeyException;

@ProtocolType("add_device")
@Doc("Link a new device to a local Signal account")
public class AddLinkedDeviceRequest implements RequestType<Empty> {
  @ExampleValue(ExampleValue.LOCAL_PHONE_NUMBER) @Doc("The account to interact with") @Required public String account;

  @ExampleValue(ExampleValue.LINKING_URI) @Doc("the tsdevice:/ uri provided (typically in qr code form) by the new device") @Required public String uri;

  @Override
  public Empty run(Request request) throws SQLException, IOException, NoSuchAccount, URISyntaxException, InvalidInputException, InvalidKeyException, ServerNotFoundException,
                                           InvalidProxyException, NoSuchAccountException {
    Manager m = Utils.getManager(account);
    m.addDeviceLink(new URI(uri));
    return new Empty();
  }
}
