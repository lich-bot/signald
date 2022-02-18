#!/usr/bin/env bash
set -exuo pipefail

if [ "${SIGNALD_DATABASE:-}" == "postgres*" && -f "/signald/signald.db" ]; then
  echo "signald is configured to use a postgres database, but a sqlite file was found. running migration before starting"
  signaldctl db-migrate "${SIGNALD_DATABASE}" /signald/signald.db
  rm /signald/signald.db
fi

/usr/local/bin/signald -d /signald -s /signald/signald.sock