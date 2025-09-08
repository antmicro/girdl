#!/usr/bin/env bash

# This script will run checkstyle, find all files that miss a header (license),
# then automatically apply that header. This will only work if the header is missing not malformed
# as then it would have prepended another header and made things worse,
# in those cases the script will just print the file path for the caller to investigate manually.

echo "Info: Running checkstyle, please wait..."
code=0

# Redirect stderr, discard stdout
for path in $(./gradlew -q checkstyleMain 2>&1 >/dev/null | grep "\[Header]" | cut -d: -f2 | cut -d] -f3 | cut -c 1-) ; do
  if head -n 1 < "$path" | grep -q '^package'; then
      cat config/checkstyle/header.java $path > "$path.fixup"
      rm $path
      mv "$path.fixup" $path
      echo "Info: Added license to $path"
  else
    echo "Error: Unable to add license to $path!"
    code=1
  fi
done

exit $code