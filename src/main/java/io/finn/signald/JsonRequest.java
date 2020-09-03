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

import io.finn.signald.clientprotocol.v1.JsonAddress;
import io.finn.signald.clientprotocol.v1.JsonReaction;
import io.finn.signald.storage.ContactStore;

import java.util.List;


public class JsonRequest {
    public String type;
    public String id;
    public String username;
    public String messageBody;
    public String recipientGroupId;
    public JsonAddress recipientAddress;
    public Boolean voice;
    public String code;
    public String deviceName;
    public List<JsonAttachment> attachments;
    public String uri;
    public String groupName;
    public List<String> members;
    public String avatar;
    public JsonQuote quote;
    public int expiresInSeconds;
    public String fingerprint;
    public String trustLevel;
    public ContactStore.ContactInfo contact;
    public String captcha;
    public String name;
    public List<Long> timestamps;
    public long when;
    public JsonReaction reaction;
    public String pin;

    JsonRequest() {}
}
