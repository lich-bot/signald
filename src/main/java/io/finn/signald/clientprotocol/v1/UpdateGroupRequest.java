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

import static io.finn.signald.annotations.ExactlyOneOfRequired.GROUP_MODIFICATION;

import io.finn.signald.Manager;
import io.finn.signald.annotations.*;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.db.Recipient;
import io.finn.signald.db.RecipientsTable;
import io.finn.signald.storage.AccountData;
import io.finn.signald.storage.Group;
import io.finn.signald.storage.ProfileAndCredentialEntry;
import io.finn.signald.util.GroupsUtil;
import java.io.IOException;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asamk.signal.GroupNotFoundException;
import org.asamk.signal.NotAGroupMemberException;
import org.signal.storageservice.protos.groups.AccessControl;
import org.signal.storageservice.protos.groups.Member;
import org.signal.zkgroup.VerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.util.Base64;

@ProtocolType("update_group")
@Doc("modify a group. Note that only one modification action may be performed at once")
public class UpdateGroupRequest implements RequestType<GroupInfo> {
  private static final Logger logger = LogManager.getLogger();

  @ExampleValue(ExampleValue.LOCAL_PHONE_NUMBER) @Doc("The identifier of the account to interact with") @Required public String account;

  @ExampleValue(ExampleValue.GROUP_ID) @Doc("the ID of the group to update") @Required public String groupID;

  @ExampleValue(ExampleValue.GROUP_TITLE) @ExactlyOneOfRequired(GROUP_MODIFICATION) public String title;

  @ExampleValue(ExampleValue.GROUP_DESCRIPTION)
  @ExactlyOneOfRequired(GROUP_MODIFICATION)
  @Doc("A new group description. Set to empty string to remove an existing description.")
  public String description;

  @ExampleValue(ExampleValue.LOCAL_EXTERNAL_JPG) @ExactlyOneOfRequired(GROUP_MODIFICATION) public String avatar;

  @Doc("update the group timer.") @ExactlyOneOfRequired(GROUP_MODIFICATION) public int updateTimer = -1;

  @ExactlyOneOfRequired(GROUP_MODIFICATION) public List<JsonAddress> addMembers;

  @ExactlyOneOfRequired(GROUP_MODIFICATION) public List<JsonAddress> removeMembers;

  @ExactlyOneOfRequired(GROUP_MODIFICATION) public GroupMember updateRole;

  @Doc("note that only one of the access controls may be updated per request") @ExactlyOneOfRequired(GROUP_MODIFICATION) public GroupAccessControl updateAccessControl;

  @Doc("regenerate the group link password, invalidating the old one") @ExactlyOneOfRequired(GROUP_MODIFICATION) public boolean resetLink;

  @Override
  public GroupInfo run(Request request) throws InvalidKeyException, IOException, InvalidProxyException, SQLException, NoSuchAccount, ServerNotFoundException,
                                               NotAGroupMemberException, GroupNotFoundException, io.finn.signald.exceptions.UnknownGroupException, UnknownGroupException,
                                               VerificationFailedException, InterruptedException, ExecutionException, TimeoutException, InvalidRequestException {
    Manager m = Utils.getManager(account);
    AccountData accountData = m.getAccountData();
    RecipientsTable recipientsTable = m.getRecipientsTable();

    if (groupID.length() == 24) { // v1 group
      List<Recipient> addMembersSignalServiceAddress = null;
      if (addMembers != null) {
        addMembersSignalServiceAddress = new ArrayList<>();

        for (JsonAddress member : addMembers) {
          addMembersSignalServiceAddress.add(recipientsTable.get(member));
        }
      }
      io.finn.signald.storage.GroupInfo g = m.sendUpdateGroupMessage(Base64.decode(groupID), title, addMembersSignalServiceAddress, avatar);
      return new GroupInfo(g);
    } else {
      Group group;
      try {
        group = accountData.groupsV2.get(groupID);
      } catch (io.finn.signald.exceptions.UnknownGroupException e) {
        throw new UnknownGroupException();
      }
      if (group == null) {
        throw new UnknownGroupException();
      }

      List<Recipient> recipients = recipientsTable.get(group.group.getMembersList().stream().map(GroupsUtil::getMemberAddress).collect(Collectors.toList()));
      Pair<SignalServiceDataMessage.Builder, Group> output;

      if (title != null) {
        output = m.getGroupsV2Manager().updateTitle(groupID, title);
      } else if (description != null) {
        output = m.getGroupsV2Manager().updateDescription(groupID, description);
      } else if (avatar != null) {
        output = m.getGroupsV2Manager().updateAvatar(groupID, avatar);
      } else if (addMembers != null && addMembers.size() > 0) {
        List<ProfileAndCredentialEntry> members = new ArrayList<>();
        for (JsonAddress member : addMembers) {
          Recipient recipient = recipientsTable.get(member);
          ProfileAndCredentialEntry profileAndCredentialEntry = m.getRecipientProfileKeyCredential(recipient);
          if (profileAndCredentialEntry == null) {
            logger.warn("Unable to add group member with no profile");
            continue;
          }
          members.add(profileAndCredentialEntry);
          recipients.add(recipientsTable.get(profileAndCredentialEntry.getServiceAddress()));
        }
        output = m.getGroupsV2Manager().addMembers(groupID, members);
      } else if (removeMembers != null && removeMembers.size() > 0) {
        Set<UUID> members = new HashSet<>();
        for (JsonAddress member : removeMembers) {
          Recipient recipient = recipientsTable.get(member);
          members.add(recipient.getUUID());
        }
        output = m.getGroupsV2Manager().removeMembers(groupID, members);
      } else if (updateRole != null) {
        UUID uuid = UUID.fromString(updateRole.uuid);
        Member.Role role;
        switch (updateRole.role) {
        case "ADMINISTRATOR":
          role = Member.Role.ADMINISTRATOR;
          break;
        case "DEFAULT":
          role = Member.Role.DEFAULT;
          break;
        default:
          throw new InvalidRequestException("unknown role requested");
        }
        output = m.getGroupsV2Manager().changeRole(groupID, uuid, role);
      } else if (updateAccessControl != null) {
        if (updateAccessControl.attributes != null) {
          if (updateAccessControl.members != null || updateAccessControl.link != null) {
            throw new InvalidRequestException("only one access control may be updated at once");
          }
          output = m.getGroupsV2Manager().updateAccessControlAttributes(groupID, getAccessRequired(updateAccessControl.attributes));
        } else if (updateAccessControl.members != null) {
          if (updateAccessControl.link != null) {
            throw new InvalidRequestException("only one access control may be updated at once");
          }
          output = m.getGroupsV2Manager().updateAccessControlMembership(groupID, getAccessRequired(updateAccessControl.members));
        } else if (updateAccessControl.link != null) {
          output = m.getGroupsV2Manager().updateAccessControlJoinByLink(groupID, getAccessRequired(updateAccessControl.link));
        } else {
          throw new InvalidRequestException("no known access control requested");
        }
      } else if (resetLink) {
        output = m.getGroupsV2Manager().resetGroupLinkPassword(groupID);
      } else if (updateTimer > -1) {
        output = m.getGroupsV2Manager().updateGroupTimer(groupID, updateTimer);
      } else {
        throw new InvalidRequestException("no change requested");
      }

      m.sendGroupV2Message(output.first(), output.second().getSignalServiceGroupV2(), recipients);

      accountData.groupsV2.update(output.second());
      accountData.save();
      return new GroupInfo(group.getJsonGroupV2Info(m));
    }
  }

  public AccessControl.AccessRequired getAccessRequired(String name) throws InvalidRequestException {
    switch (name) {
    case "ANY":
      return AccessControl.AccessRequired.ANY;
    case "MEMBER":
      return AccessControl.AccessRequired.MEMBER;
    case "ADMINISTRATOR":
      return AccessControl.AccessRequired.ADMINISTRATOR;
    case "UNSATISFIABLE":
      return AccessControl.AccessRequired.UNSATISFIABLE;
    default:
      throw new InvalidRequestException("invalid role: " + name);
    }
  }
}
