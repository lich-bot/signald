/**
 * Copyright (C) 2018 Finn Herzfeld
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

public class JsonAccount {
  public int deviceId;
  public String username;
  public String filename;
  public boolean registered;
  public boolean has_keys;
  public boolean subscribed;

  public JsonAccount(Manager m) {
    this.username = m.getUsername();
    this.deviceId = m.getDeviceId();
    this.filename = m.getFileName();
    this.registered = m.isRegistered();
    this.has_keys = m.userHasKeys();
  }

  public JsonAccount(Manager m, boolean subscribed) {
    this(m);
    this.subscribed = subscribed;
  }

}
