package io.finn.signald.clientprotocol.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;
import org.signal.storageservice.protos.groups.local.DecryptedPendingMember;
import org.whispersystems.signalservice.api.util.UuidUtil;

public class GroupPendingMember {
  @ExampleValue(ExampleValue.REMOTE_UUID) public String uuid;
  @ExampleValue("\"DEFAULT\"") @Doc("possible values are: UNKNOWN, DEFAULT, ADMINISTRATOR and UNRECOGNIZED") public String role;
  @JsonProperty("added_by_uuid") @ExampleValue(ExampleValue.REMOTE_UUID) public String addedByUuid;
  public long timestamp;

  public GroupPendingMember(DecryptedPendingMember d) {
    uuid = UuidUtil.fromByteStringOrUnknown(d.serviceIdBytes).toString();
    role = d.role.name();
    addedByUuid = UuidUtil.fromByteStringOrUnknown(d.addedByAci).toString();
    timestamp = d.timestamp;
  }
}
