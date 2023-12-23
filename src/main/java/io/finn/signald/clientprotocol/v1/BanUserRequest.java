package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.Account;
import io.finn.signald.annotations.*;
import io.finn.signald.clientprotocol.Request;
import io.finn.signald.clientprotocol.RequestType;
import io.finn.signald.clientprotocol.v1.exceptions.*;
import io.finn.signald.clientprotocol.v1.exceptions.InternalError;
import io.finn.signald.db.Database;
import java.io.IOException;
import java.sql.SQLException;
import java.util.*;
import okio.ByteString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.storageservice.protos.groups.GroupChange;
import org.signal.storageservice.protos.groups.local.DecryptedBannedMember;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.api.util.UuidUtil;

@ProtocolType("ban_user")
@Doc("Bans users from a group. This works even if the users aren't in the group. If they are currently in the group, they will also be removed.")
@ErrorDoc(error = AuthorizationFailedError.class, doc = AuthorizationFailedError.DEFAULT_ERROR_DOC)
@ErrorDoc(error = GroupPatchNotAcceptedError.class, doc = GroupPatchNotAcceptedError.DEFAULT_ERROR_DOC)
public class BanUserRequest implements RequestType<JsonGroupV2Info> {
  private static final Logger logger = LogManager.getLogger();

  @ExampleValue(ExampleValue.LOCAL_UUID) @Doc("The account to interact with") @Required public String account;

  @ExampleValue(ExampleValue.GROUP_ID) @JsonProperty("group_id") @Required public String groupId;

  @Required @Doc("List of users to ban") @JsonProperty("users") public List<JsonAddress> usersToBan;

  @Override
  public JsonGroupV2Info run(Request request) throws NoSuchAccountError, ServerNotFoundError, InvalidProxyError, UnknownGroupError, GroupVerificationError, InternalError,
                                                     InvalidRequestError, AuthorizationFailedError, SQLError, GroupPatchNotAcceptedError {
    final Account a = Common.getAccount(account);
    final var group = Common.getGroup(a, groupId);
    final var decryptedGroup = group.getDecryptedGroup();

    var recipientsTable = Database.Get(a.getACI()).RecipientsTable;
    final Set<ServiceId.ACI> allUsersToBan = new HashSet<>(this.usersToBan.size());
    for (JsonAddress user : this.usersToBan) {
      try {
        allUsersToBan.add(recipientsTable.get(user).getACI());
      } catch (UnregisteredUserException e) {
        logger.info("Unregistered user");
        // allow banning users if they end up unregistered, because they can just register again
        if (user.getUUID() == null) {
          throw new InvalidRequestError("One of the input users is unregistered and we don't know their service identifier / UUID!");
        }
        allUsersToBan.add(user.getACI());
      } catch (SQLException | IOException e) {
        throw new InternalError("error looking up user", e);
      }
    }

    final var groupOperations = Common.getGroupOperations(a, group);

    // have to simultaneously ban and remove users that are in the group membership lists
    final var finalChange = new GroupChange.Actions.Builder();
    for (ServiceId.ACI userToBan : allUsersToBan) {
      final ByteString userToBanUuidBytes = userToBan.toByteString();
      DecryptedBannedMember decryptedBannedMember = new DecryptedBannedMember.Builder().serviceIdBytes(userToBanUuidBytes).build();
      final GroupChange.Actions.Builder thisChange;
      if (decryptedGroup.members.stream().anyMatch(member -> member.aciBytes.equals(userToBanUuidBytes))) {
        // builder: addAllDeleteMembers + addAllAddBannedMembers
        thisChange = groupOperations.createRemoveMembersChange(Collections.singleton(userToBan), true, Collections.singletonList(decryptedBannedMember));
      } else if (decryptedGroup.requestingMembers.stream().anyMatch(requesting -> requesting.aciBytes.equals(userToBanUuidBytes))) {
        // builder: addAllDeleteRequestingMembers + addAllAddBannedMembers
        thisChange = groupOperations.createRefuseGroupJoinRequest(Collections.singleton(userToBan), true, Collections.singletonList(decryptedBannedMember));
      } else {
        final var pending = decryptedGroup.pendingMembers.stream().filter(pendingMember -> pendingMember.serviceIdBytes.equals(userToBanUuidBytes)).findFirst();
        if (pending.isPresent()) {
          // builder: addAllDeletePendingMembers + addAllAddBannedMembers
          try {
            // doesn't come with alsoBan parameter
            thisChange =
                groupOperations.createRemoveInvitationChange(Collections.singleton(new UuidCiphertext(pending.get().serviceIdCipherText.toByteArray())))
                    .addBannedMembers(
                        groupOperations.createBanServiceIdsChange(Collections.singleton(userToBan), true, Collections.singletonList(decryptedBannedMember)).addBannedMembers);
          } catch (InvalidInputException e) {
            throw new InternalError("failed to get UuidCiphertext", e);
          }
        } else {
          // builder: addAllAddBannedMembers
          // ban them even though they're not in the group
          thisChange = groupOperations.createBanServiceIdsChange(Collections.singleton(userToBan), false, Collections.singletonList(decryptedBannedMember));
        }
      }

      // some of these lists might be empty from the branching above
      finalChange.addBannedMembers(thisChange.addBannedMembers)
          .deleteBannedMembers(thisChange.deleteBannedMembers)
          .deleteRequestingMembers(thisChange.deleteRequestingMembers)
          .deletePendingMembers(thisChange.deletePendingMembers);
    }

    finalChange.sourceServiceId(UuidUtil.toByteString(a.getUUID()));

    Common.updateGroup(a, group, finalChange);

    return group.getJsonGroupV2Info();
  }
}
