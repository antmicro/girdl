#!/usr/bin/env bash

mode='build'

if [[ -z "${GHIDRA_INSTALL_DIR}" ]]; then
  echo "Ghidra install dir not set!"
  exit 1
fi

while getopts 'rd' flag; do
  case "${flag}" in
    r) mode='debug' ;;
    d) mode='debug-suspend' ;;
    *) echo "Usage: $0 [-rd]"
       exit 1 ;;
  esac
done

GHIDRA_CONFIG="$HOME/.config/ghidra"
GHIDRA_EXTENSIONS="$GHIDRA_INSTALL_DIR/Extensions/Ghidra"

if [[ ! -d "$GHIDRA_CONFIG" ]]; then
  echo "Ghidra config directory not found, unable to automatically install extension!"
  echo " * Tried: '$GHIDRA_CONFIG'"
  exit 1
fi

SCRIPT_PATH="$(dirname -- "${BASH_SOURCE[0]}")"
ROOT_PATH="$(cd -- "$SCRIPT_PATH/.." && pwd)"

echo
echo "Assuming Ghidra config path to be:     $GHIDRA_CONFIG"
echo "Assuming Ghidra extension path to be:  $GHIDRA_EXTENSIONS"
echo "Assuming plugin repository path to be: $ROOT_PATH"
echo

./gradlew distributeExtension

if [[ ! $? -eq 0 ]]; then
  exit 1
fi

rm "$GHIDRA_EXTENSIONS/girdl.zip"

echo
echo "Updating plugin installations..."
for path in $(find $GHIDRA_CONFIG -maxdepth 1 -type d -name "ghidra_*" -exec echo "{}/Extensions" \;); do

  pushd "$path" >/dev/null 2>&1 || {
    echo " * Unable to update plugin installed at: $path";
    continue
  }

  echo " * Updating plugin installed at '$path'"

  if [[ -d "girdl" ]]; then
    rm -rf "girdl"
  fi

  unzip "$ROOT_PATH/dist/girdl.zip" 1>/dev/null
  popd >/dev/null 2>&1 || exit 1
done

if [[ "$mode" != "build" ]]; then
  echo
  echo "Starting Ghidra with extension enabled in $mode mode..."
  echo "Installation directory: '$GHIDRA_INSTALL_DIR'"
  echo

  "$GHIDRA_INSTALL_DIR/support/launch.sh" $mode jdk Ghidra 4G "" ghidra.GhidraRun
fi
