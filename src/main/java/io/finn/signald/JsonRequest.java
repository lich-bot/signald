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

import org.asamk.signal.storage.contacts.ContactInfo;

import java.util.List;


public class JsonRequest {
    public String type;
    public String id;
    public String username;
    public String messageBody;
    public String recipientNumber;
    public String recipientGroupId;
    public Boolean voice;
    public String code;
    public String deviceName;
    public List<String> attachmentFilenames;
    public List<JsonAttachment> attachments;
    public String uri;
    public String groupName;
    public List<String> members;
    public String avatar;
    public JsonQuote quote;
    public int expiresInSeconds;
    public String fingerprint;
    public ContactInfo contact;

    JsonRequest() {}
}
