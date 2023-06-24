#!/bin/sh

set -e

for file in *.log; do
  sed -E -i 's/\/[0-9]+/\/X/g' "$file"
  sed -E -i 's/PID [0-9]+/PID X/g' "$file"
  sed -E -i 's/[^ "]+Z/Z/g' "$file"
  sed -E -i 's/: [^:]+[0-9]+:[0-9]+:[0-9]+ UTC .+/: Z/g' "$file"
  sort -u -o "$file" "$file"
  diff "$file" "tests/$file"
done
