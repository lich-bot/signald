/*
 * // Copyright 2021 signald contributors
 * // SPDX-License-Identifier: GPL-3.0-only
 * // See included LICENSE file
 */

package io.finn.signald.clientprotocol.v2alpha1.exceptions;

public class OwnProfileKeyDoesNotExistError extends ExceptionWrapper {
  public OwnProfileKeyDoesNotExistError() { super("cannot find own profile key"); }
}
