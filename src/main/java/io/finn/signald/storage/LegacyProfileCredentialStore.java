/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.storage;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.finn.signald.Account;
import io.finn.signald.db.Database;
import io.finn.signald.db.IProfileCapabilitiesTable;
import io.finn.signald.db.Recipient;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
@Deprecated
public class LegacyProfileCredentialStore {
  private final static Logger logger = LogManager.getLogger();
  private static boolean unsaved = false;
  public final List<LegacyProfileAndCredentialEntry> profiles = new ArrayList<>();
  @JsonIgnore private Recipient self;

  public boolean migrateToDB(Account account) throws SQLException, IOException {
    Database db = account.getDB();
    if (profiles.size() > 0) {
      logger.info("Migrating {} profiles to database", profiles.size());
    }
    for (LegacyProfileAndCredentialEntry entry : profiles) {
      Recipient r = db.RecipientsTable.get(entry.getServiceAddress());
      // profile key credential format changed, dont try to migrate it
      //      db.ProfileKeysTable.setExpiringProfileKeyCredential(r, entry.getProfileKeyCredential());
      db.ProfileKeysTable.setUnidentifiedAccessMode(r, entry.getUnidentifiedAccessMode().migrate());
      db.ProfileKeysTable.setRequestPending(r, entry.isRequestPending());

      LegacySignalProfile profile = entry.getProfile();
      if (profile != null) {
        db.ProfilesTable.setSerializedName(r, profile.getName());
        db.ProfilesTable.setEmoji(r, profile.getEmoji());
        db.ProfilesTable.setAbout(r, profile.getAbout());
        db.ProfilesTable.setPaymentAddress(r, profile.getPaymentAddress());

        db.ProfileCapabilitiesTable.set(r, new IProfileCapabilitiesTable.Capabilities(profile.getCapabilities()));
      }
    }
    return true;
  }

  void initialize(Recipient self) { this.self = self; }
}
