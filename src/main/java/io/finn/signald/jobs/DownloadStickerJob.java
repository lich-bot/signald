/*
 * Copyright 2022 signald contributors
 * SPDX-License-Identifier: GPL-3.0-only
 * See included LICENSE file
 *
 */

package io.finn.signald.jobs;

import io.finn.signald.Account;
import io.finn.signald.Manager;
import io.finn.signald.MessageReceiver;
import io.finn.signald.exceptions.InvalidProxyException;
import io.finn.signald.exceptions.NoSuchAccountException;
import io.finn.signald.exceptions.ServerNotFoundException;
import io.finn.signald.util.FileUtil;
import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.push.ServiceId;
import org.whispersystems.signalservice.api.push.exceptions.MissingConfigurationException;

public class DownloadStickerJob implements Job {
  ServiceId.ACI aci;
  SignalServiceDataMessage.Sticker sticker;

  public DownloadStickerJob(ServiceId.ACI aci, SignalServiceDataMessage.Sticker sticker) {
    this.aci = aci;
    this.sticker = sticker;
  }

  @Override
  public void run() throws IOException, SQLException, NoSuchAccountException, MissingConfigurationException, InvalidMessageException, ServerNotFoundException, InvalidKeyException,
                           InvalidProxyException {
    File stickerFile = FileUtil.getStickerFile(sticker);
    new MessageReceiver(aci).retrieveAttachment(sticker.getAttachment(), stickerFile);
  }

  public boolean needsDownload() { return !Manager.getStickerFile(sticker).exists(); }
}
