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
  # We sort files to remove order differences and remove duplicate lines.
  sort -u -o "$file" "$file"
done

ret=0
for file in *.log; do
  match=0
  for result in tests/results/$(basename "$file" .log)-*.log; do
    if diff "$file" "$result" > /dev/null 2>&1 ; then
      match=1
      break
    fi
  done
  if [ "$match" = 0 ]; then
    echo "$file: ERROR"
    ret=1
  else
    echo "$file: OK"
  fi
done

exit $ret
