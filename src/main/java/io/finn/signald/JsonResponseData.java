/*
 * Copyright (C) 2020 Finn Herzfeld
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

import io.finn.signald.clientprotocol.v1.JsonSendMessageResult;
import io.finn.signald.storage.ContactStore;

import java.util.List;

public class JsonResponseData {
    public List<ContactStore.ContactInfo> contacts;
    public List<JsonGroupInfo> groups;
	public List<JsonAccount> accounts;
    public List<JsonIdentity> identities;
    public List<JsonSendMessageResult> sendresults;
    public JsonStatusMessage statusmessage;
    public JsonContactTokenDetails contacttokendetails;
    public JsonProfile profile;
    public JsonVersionMessage version;
    public JsonUntrustedIdentityException untrustedidentityexception;
    public String uri;

    JsonResponseData() {}
}
