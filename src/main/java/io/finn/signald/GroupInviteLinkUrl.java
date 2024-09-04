/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import kotlin.reflect.jvm.internal.impl.storage.NullableLazyValue;
import okio.ByteString;
import org.signal.core.util.Base64;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.GroupMasterKey;
import org.signal.storageservice.protos.groups.GroupInviteLink;
import org.signal.storageservice.protos.groups.local.DecryptedGroup;

public final class GroupInviteLinkUrl {

  private static final String GROUP_URL_HOST = "signal.group";
  private static final String GROUP_URL_PREFIX = "https://" + GROUP_URL_HOST + "/#";

  private final GroupMasterKey groupMasterKey;
  private final GroupLinkPassword password;
  private final String url;

  public static GroupInviteLinkUrl forGroup(GroupMasterKey groupMasterKey, DecryptedGroup group) {
    return new GroupInviteLinkUrl(groupMasterKey, GroupLinkPassword.fromBytes(group.inviteLinkPassword.toByteArray()));
  }

  public static boolean isGroupLink(String urlString) { return getGroupUrl(urlString) != null; }

  /**
   * @return null iff not a group url.
   * @throws InvalidGroupLinkException If group url, but cannot be parsed.
   */
  public static GroupInviteLinkUrl fromUri(String urlString) throws InvalidGroupLinkException, UnknownGroupLinkVersionException {
    URI uri = getGroupUrl(urlString);

    if (uri == null) {
      return null;
    }

    try {
      if (!"/".equals(uri.getPath()) && uri.getPath().length() > 0) {
        throw new InvalidGroupLinkException("No path was expected in uri");
      }

      String encoding = uri.getFragment();

      if (encoding == null || encoding.length() == 0) {
        throw new InvalidGroupLinkException("No reference was in the uri");
      }

      byte[] bytes = Base64.decode(encoding);
      GroupInviteLink groupInviteLink = GroupInviteLink.ADAPTER.decode(bytes);

      GroupInviteLink.GroupInviteLinkContentsV1 groupInviteLinkContentsV1 = groupInviteLink.v1Contents;
      GroupMasterKey groupMasterKey = new GroupMasterKey(groupInviteLinkContentsV1.groupMasterKey.toByteArray());
      GroupLinkPassword password = GroupLinkPassword.fromBytes(groupInviteLinkContentsV1.inviteLinkPassword.toByteArray());

      return new GroupInviteLinkUrl(groupMasterKey, password);
    } catch (InvalidInputException | IOException e) {
      throw new InvalidGroupLinkException(e);
    }
  }

  /**
   * @return {@link URI} if the host name matches.
   */
  private static URI getGroupUrl(String urlString) {
    try {
      URI url = new URI(urlString);

      if (!"https".equalsIgnoreCase(url.getScheme()) && !"sgnl".equalsIgnoreCase(url.getScheme())) {
        return null;
      }

      return GROUP_URL_HOST.equalsIgnoreCase(url.getHost()) ? url : null;
    } catch (URISyntaxException e) {
      return null;
    }
  }

  private GroupInviteLinkUrl(GroupMasterKey groupMasterKey, GroupLinkPassword password) {
    this.groupMasterKey = groupMasterKey;
    this.password = password;
    this.url = createUrl(groupMasterKey, password);
  }

  protected static String createUrl(GroupMasterKey groupMasterKey, GroupLinkPassword password) {
    GroupInviteLink groupInviteLink = new GroupInviteLink.Builder()
                                          .v1Contents(new GroupInviteLink.GroupInviteLinkContentsV1.Builder()
                                                          .groupMasterKey(ByteString.of(groupMasterKey.serialize()))
                                                          .inviteLinkPassword(ByteString.of(password.serialize()))
                                                          .build())
                                          .build();
    String encoding = Base64.encodeUrlSafeWithoutPadding(groupInviteLink.encode());

    return GROUP_URL_PREFIX + encoding;
  }

  public String getUrl() { return url; }

  public GroupMasterKey getGroupMasterKey() { return groupMasterKey; }

  public GroupLinkPassword getPassword() { return password; }

  public final static class InvalidGroupLinkException extends Exception {

    public InvalidGroupLinkException(String message) { super(message); }

    public InvalidGroupLinkException(Throwable cause) { super(cause); }
  }

  public final static class UnknownGroupLinkVersionException extends Exception {

    public UnknownGroupLinkVersionException(String message) { super(message); }
  }
}
