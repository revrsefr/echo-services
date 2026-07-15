#!/usr/bin/env bash
# Back up Echo's event log. The log is append-only, and compaction replaces it
# atomically (temp file + rename), so a plain copy is a consistent snapshot; a
# copy taken mid-append has at most a truncated final line, which Echo skips on
# load. Run from cron or a systemd timer, e.g. hourly.
#
#   ECHO_DATA_DIR=/opt/echo ECHO_BACKUP_DIR=/opt/echo/backups ./backup.sh
#
# Restore: stop the service, gunzip a backup over the live log, start again:
#   systemctl stop echo
#   gunzip -c /opt/echo/backups/echo.db.<stamp>.jsonl.gz > /opt/echo/echo.db.jsonl
#   systemctl start echo
set -euo pipefail

DATA_DIR="${ECHO_DATA_DIR:-/opt/echo}"
BACKUP_DIR="${ECHO_BACKUP_DIR:-$DATA_DIR/backups}"
KEEP="${ECHO_BACKUP_KEEP:-48}"
LOG="$DATA_DIR/echo.db.jsonl"

[ -f "$LOG" ] || { echo "no event log at $LOG" >&2; exit 1; }
mkdir -p "$BACKUP_DIR"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
dest="$BACKUP_DIR/echo.db.$stamp.jsonl.gz"
gzip -c "$LOG" > "$dest.tmp"
mv "$dest.tmp" "$dest"
echo "backed up $LOG -> $dest ($(du -h "$dest" | cut -f1))"

# Keep the most recent $KEEP backups.
ls -1t "$BACKUP_DIR"/echo.db.*.jsonl.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f
