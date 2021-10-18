/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.util;

import io.finn.signald.annotations.ProtocolType;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class RequestUtil {
  public static final List<Class<? extends io.finn.signald.clientprotocol.RequestType<?>>> REQUEST_TYPES = Arrays.asList( // version   request_type

      // v1
      io.finn.signald.clientprotocol.v1.SendRequest.class,               // v1        send
      io.finn.signald.clientprotocol.v1.ReactRequest.class,              // v1        react
      io.finn.signald.clientprotocol.v1.VersionRequest.class,            // v1        version
      io.finn.signald.clientprotocol.v1.AcceptInvitationRequest.class,   // v1        accept_invitation
      io.finn.signald.clientprotocol.v1.ApproveMembershipRequest.class,  // v1        approve_membership
      io.finn.signald.clientprotocol.v1.GetGroupRequest.class,           // v1        get_group
      io.finn.signald.clientprotocol.v1.GetLinkedDevicesRequest.class,   // v1        get_linked_devices
      io.finn.signald.clientprotocol.v1.JoinGroupRequest.class,          // v1        join_group
      io.finn.signald.clientprotocol.v1.ProtocolRequest.class,           // v1        protocol
      io.finn.signald.clientprotocol.v1.RemoveLinkedDeviceRequest.class, // v1        remove_linked_device
      io.finn.signald.clientprotocol.v1.UpdateGroupRequest.class,        // v1        update_group
      io.finn.signald.clientprotocol.v1.SetProfile.class,                // v1        set_profile
      io.finn.signald.clientprotocol.v1.ResolveAddressRequest.class,     // v1        resolve_address
      io.finn.signald.clientprotocol.v1.MarkReadRequest.class,           // v1        mark_read
      io.finn.signald.clientprotocol.v1.GetProfileRequest.class,         // v1        get_profile
      io.finn.signald.clientprotocol.v1.ListGroupsRequest.class,         // v1        list_groups
      io.finn.signald.clientprotocol.v1.ListContactsRequest.class,       // v1        list_contacts
      io.finn.signald.clientprotocol.v1.CreateGroupRequest.class,        // v1        create_group
      io.finn.signald.clientprotocol.v1.LeaveGroupRequest.class,         // v1        leave_group
      io.finn.signald.clientprotocol.v1.GenerateLinkingURIRequest.class, // v1        generate_linking_uri
      io.finn.signald.clientprotocol.v1.FinishLinkRequest.class,         // v1        finish_link
      io.finn.signald.clientprotocol.v1.AddLinkedDeviceRequest.class,    // v1        add_device
      io.finn.signald.clientprotocol.v1.RegisterRequest.class,           // v1        register
      io.finn.signald.clientprotocol.v1.VerifyRequest.class,             // v1        verify
      io.finn.signald.clientprotocol.v1.GetIdentitiesRequest.class,      // v1        get_identities
      io.finn.signald.clientprotocol.v1.TrustRequest.class,              // v1        trust
      io.finn.signald.clientprotocol.v1.DeleteAccountRequest.class,      // v1        delete_account
      io.finn.signald.clientprotocol.v1.TypingRequest.class,             // v1        typing
      io.finn.signald.clientprotocol.v1.ResetSessionRequest.class,       // v1        reset_session
      io.finn.signald.clientprotocol.v1.RequestSyncRequest.class,        // v1        request_sync
      io.finn.signald.clientprotocol.v1.ListAccountsRequest.class,       // v1        list_accounts
      io.finn.signald.clientprotocol.v1.GroupLinkInfoRequest.class,      // v1        group_link_info
      io.finn.signald.clientprotocol.v1.UpdateContactRequest.class,      // v1        update_contact
      io.finn.signald.clientprotocol.v1.SetExpirationRequest.class,      // v1        set_expiration
      io.finn.signald.clientprotocol.v1.SetDeviceNameRequest.class,      // v1        set_device_name
      io.finn.signald.clientprotocol.v1.GetAllIdentities.class,          // v1        get_all_identities
      io.finn.signald.clientprotocol.v1.SubscribeRequest.class,          // v1        subscribe
      io.finn.signald.clientprotocol.v1.UnsubscribeRequest.class,        // v1        unsubscribe
      io.finn.signald.clientprotocol.v1.RemoteDeleteRequest.class,       // v1        remote_delete
      io.finn.signald.clientprotocol.v1.AddServerRequest.class,          // v1        add_server
      io.finn.signald.clientprotocol.v1.GetServersRequest.class,         // v1        get_servers
      io.finn.signald.clientprotocol.v1.RemoveServerRequest.class,       // v1        remove_server
      io.finn.signald.clientprotocol.v1.SendPaymentRequest.class,        // v1        send_payment
      io.finn.signald.clientprotocol.v1.RemoteConfigRequest.class,       // v1        get_remote_config
      io.finn.signald.clientprotocol.v1.RefuseMembershipRequest.class,   // v1        refuse_membership
      io.finn.signald.clientprotocol.v1.SubmitChallengeRequest.class,    // v1        submit_challenge

      // v2alpha1
      io.finn.signald.clientprotocol.v2alpha1.BinaryUploadRequest.class, // v2alpha1  binary_upload
      io.finn.signald.clientprotocol.v2alpha1.SendMessageRequest.class   // v2alpha1 send_message
  );

  public static String getVersion(Class<?> t) {
    if (t == null || t.isPrimitive() || t == UUID.class || t == Map.class) {
      return null;
    }
    String pkg = t.getName().replace("." + t.getSimpleName(), "");
    if (pkg.equals("java.lang")) {
      return null;
    }

    if (!pkg.startsWith("io.finn.signald.clientprotocol")) {
      return "v0";
    }

    pkg = pkg.replace("io.finn.signald.clientprotocol.", "");
    pkg = pkg.replace(".exceptions", "");
    if (!pkg.contains(".")) {
      return pkg;
    }
    return pkg.substring(0, pkg.indexOf("."));
  }

  public static String getType(Class<?> t) {
    ProtocolType annotation = t.getAnnotation(ProtocolType.class);
    if (annotation == null) {
      return t.getSimpleName();
    }
    return annotation.value();
  }
}
