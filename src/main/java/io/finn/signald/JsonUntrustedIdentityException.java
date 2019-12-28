/**
 * Copyright (C) 2019 Finn Herzfeld
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

package io.finn.signald;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.libsignal.IdentityKey;
import org.asamk.signal.util.Hex;


class JsonUntrustedIdentityException {
  public String username;
  public String number;
  public String fingerprint;
  public String safety_number;
  public JsonRequest request;

  JsonUntrustedIdentityException(IdentityKey key, String number, Manager m, JsonRequest request) {
    this.username = m.getUsername();
    this.number = number;
    this.fingerprint = Hex.toStringCondensed(key.getPublicKey().serialize());
    this.safety_number = m.computeSafetyNumber(this.number, key);
    this.request = request;
  }
}
