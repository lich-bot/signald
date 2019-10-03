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

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Enumeration;

public class JsonAccountList {
  public List<JsonAccount> accounts = new ArrayList<JsonAccount>();

  public JsonAccountList(ConcurrentHashMap<String, Manager> managers, ArrayList<String> subscribedAccounts) {
    Enumeration<String> usernames = managers.keys();
    while(usernames.hasMoreElements()) {
      String username = usernames.nextElement();
      Manager manager = managers.get(username);
      JsonAccount account = new JsonAccount(manager, subscribedAccounts.contains(username));
      accounts.add(account);
    }
  }
}
