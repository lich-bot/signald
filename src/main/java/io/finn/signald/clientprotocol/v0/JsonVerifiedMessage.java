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

package io.finn.signald.clientprotocol.v0;

import io.finn.signald.annotations.Deprecated;
import org.asamk.signal.util.Hex;
import org.whispersystems.signalservice.api.messages.multidevice.VerifiedMessage;

@Deprecated(1641027661)
public class JsonVerifiedMessage {
  public JsonAddress destination;
  public String identityKey;
  public String verified;
  public long timestamp;

  public JsonVerifiedMessage(VerifiedMessage message) {
    destination = new JsonAddress(message.getDestination());
    identityKey = Hex.toStringCondensed(message.getIdentityKey().getPublicKey().serialize());
    verified = message.getVerified().toString();
    timestamp = message.getTimestamp();
  }
}
