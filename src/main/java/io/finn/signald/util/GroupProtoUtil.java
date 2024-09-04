package io.finn.signald.util;

import io.reactivex.rxjava3.annotations.NonNull;
import java.util.List;
import java.util.UUID;
import okio.ByteString;
import org.signal.storageservice.protos.groups.local.DecryptedGroup;
import org.signal.storageservice.protos.groups.local.DecryptedMember;
import org.signal.storageservice.protos.groups.local.DecryptedPendingMember;
import org.whispersystems.signalservice.api.groupsv2.DecryptedGroupUtil;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.util.UuidUtil;
import org.whispersystems.signalservice.internal.push.exceptions.NotInGroupException;

public class GroupProtoUtil {
  public static int findRevisionWeWereAdded(@NonNull DecryptedGroup group, @NonNull UUID uuid) throws NotInGroupException {
    ByteString bytes = UuidUtil.toByteString(uuid);
    for (DecryptedMember decryptedMember : group.members) {
      if (decryptedMember.aciBytes.equals(bytes)) {
        return decryptedMember.joinedAtRevision;
      }
    }
    for (DecryptedPendingMember decryptedMember : group.pendingMembers) {
      if (decryptedMember.serviceIdBytes.equals(bytes)) {
        // Assume latest, we don't have any information about when pending members were invited
        return group.revision;
      }
    }
    throw new NotInGroupException();
  }

  public static boolean isMember(@NonNull UUID uuid, @NonNull List<DecryptedMember> membersList) {
    return DecryptedGroupUtil.findMemberByAci(membersList, ServiceId.ACI.from(uuid)).isPresent();
  }
}
