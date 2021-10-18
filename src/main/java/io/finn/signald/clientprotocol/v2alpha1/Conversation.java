/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.finn.signald.annotations.Doc;
import io.finn.signald.annotations.ExampleValue;

public class Conversation {
  @Doc("the UUID one user. Mutually exclusive with group_id") public String user;

  @JsonProperty("group_id") @Doc("a group ID. Mutually exclusive with user") @ExampleValue(ExampleValue.GROUP_ID) public String groupId;

  @JsonProperty @Doc("only available if group_id is present, indicates the revision version of the group") public Integer revision;
}
