#!/bin/sh

set -e

for file in *.log; do
  # We remove PIDs of adopted processes (they are in the form "processname/pid").
  sed -E -i 's/\/[0-9]+/\/X/g' "$file"
  # We remove PID numbers.
  sed -E -i 's/PID [0-9]+/PID X/g' "$file"
  # We remove any RFC 3339 timestamps in UTC (Z) timezone.
  sed -E -i 's/[^ "]+Z/Z/g' "$file"
  # We remove timestamps in Unix format.
  sed -E -i 's/: [^:]+[0-9]+:[0-9]+:[0-9]+ UTC .+/: Z/g' "$file"
  # Sometimes an extra date process is detected, we remove logs about is.
  sed -E -i '/date\/X/d' "$file"
  # We sort files to remove order differences and remove duplicate lines.
  sort -u -o "$file" "$file"
done

for file in *.log; do
  echo "$file"
  diff "$file" "tests/$file"
done
