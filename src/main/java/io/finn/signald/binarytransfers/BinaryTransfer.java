/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.binarytransfers;

import io.finn.signald.exceptions.StreamNotReadyException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.newsclub.net.unix.AFUNIXServerSocket;
import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;
import org.newsclub.net.unix.AFUNIXSocketCredentials;

public class BinaryTransfer implements Runnable {
  private final static Logger logger = LogManager.getLogger();
  private final static String SOCKET_DIR = "/run/user/1000/signald"; // TODO
  private static final HashMap<UUID, BinaryTransfer> transfers = new HashMap<>();

  enum Status { PENDING, STARTED, WAITING_FOR_CLIENT, CLIENT_CONNECTED, DISCONNECTED_SUCCESSFUL, DISCONNECTED_ERROR, DISCONNECTED_CANCELLED }

  private final UUID transferID;
  private final Thread thread;
  private final long size;
  private AFUNIXSocket socket = null;
  private final Object socketLock = new Object();
  private Status status;

  public BinaryTransfer(long size) {
    this.size = size;
    transferID = UUID.randomUUID();
    status = Status.PENDING;
    synchronized (transfers) { transfers.put(transferID, this); }
    thread = new Thread(this);
    thread.start();
  }

  public static BinaryTransfer get(UUID transferID) {
    synchronized (transfers) { return transfers.get(transferID); }
  }

  public UUID getTransferID() { return transferID; }

  public InputStream getInputStream() throws IOException, StreamNotReadyException {
    synchronized (socketLock) {
      if (socket == null) {
        throw new StreamNotReadyException(transferID);
      }
      return socket.getInputStream();
    }
  }

  public long getSize() { return size; }

  @Override
  public void run() {
    try {
      synchronized (socketLock) {
        status = Status.STARTED;
        AFUNIXServerSocket server = AFUNIXServerSocket.newInstance();
        server.bind(new AFUNIXSocketAddress(new File(SOCKET_DIR, transferID.toString() + ".sock")));
        status = Status.WAITING_FOR_CLIENT;
        socket = server.accept();
        status = Status.CLIENT_CONNECTED;
        AFUNIXSocketCredentials credentials = socket.getPeerCredentials();
        logger.debug("connection from pid " + credentials.getPid() + " uid " + credentials.getUid());
      }
    } catch (IOException e) {
      logger.error("error setting up binary transfer", e);
      status = Status.DISCONNECTED_ERROR;
    }
  }
}
