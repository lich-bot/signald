#!/bin/bash
#
# Copyright 2022 signald contributors
# SPDX-License-Identifier: GPL-3.0-only
# See included LICENSE file
#
#
set -euo pipefail

[[ "${1:-}" == "break" ]] && exec /bin/bash

if [[ "${SIGNALD_DATABASE:-}" == "postgres"* ]] && [[ -f "/signald/signald.db" ]]; then
  echo "signald is configured to use a postgres database, but a sqlite file was found. running migration before starting"
  signaldctl db-move "${SIGNALD_DATABASE}" /signald/signald.db || (echo "database move failed, leaving container running for 10 minutes" && sleep 600 && exit 1)
fi
if [[ $(id -u signald) ]]; then
  echo "set user id to -> $UID"
  usermod -u ${UID} signald
fi
if [[ $(id -g signald) ]]; then
  echo "set group id to -> $GID"
  groupmod -g ${GID} signald
fi
if [[ $(stat -c "%U:%G" /signald) != "signald:signald" ]]; then
  echo "fixing permissions"
  chown -R signald:signald /signald
fi

exec runuser -u signald -- signald "$@"
