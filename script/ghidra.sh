#!/usr/bin/env bash

mode='build'

if [[ ! -d "$(pwd)/ghidra/install" ]]; then
  echo "Ghidra installation not found!"
  echo " * Make sure you are running this script from the project root"
  echo " * Invoke './script/install.sh' first to install local ghidra build"
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

SCRIPT_PATH="$(dirname -- "${BASH_SOURCE[0]}")"
ROOT_PATH="$(cd -- "$SCRIPT_PATH/.." && pwd)"

INSTALL_DIR="$ROOT_PATH/ghidra/install"
GHIDRA_CONFIG="$HOME/.config/ghidra/$(cat "$ROOT_PATH/ghidra/config.txt")"
GHIDRA_EXTENSIONS="$INSTALL_DIR/Extensions/Ghidra"

if [[ ! -d "$GHIDRA_CONFIG" ]]; then
  echo "Ghidra config directory not found, unable to automatically install extension!"
  echo " * Tried: '$GHIDRA_CONFIG'"
  exit 1
fi

echo
echo "Assuming Ghidra config path to be:     $GHIDRA_CONFIG"
echo "Assuming Ghidra extension path to be:  $GHIDRA_EXTENSIONS"
echo "Assuming plugin repository path to be: $ROOT_PATH"
echo

./gradlew distribute

if [[ ! $? -eq 0 ]]; then
  echo "Failed to build the extension!"
  exit 1
fi

rm "$GHIDRA_EXTENSIONS/girdl.zip"
cp "$ROOT_PATH/dist/girdl.zip" "$GHIDRA_EXTENSIONS"

if pushd "$GHIDRA_CONFIG" >/dev/null 2>&1; then

  mkdir -p "Extensions"
  cd Extensions

  if [[ -d "girdl" ]]; then
    rm -rf "girdl"
  fi

  unzip "$ROOT_PATH/dist/girdl.zip" 1>/dev/null
  popd
else
  echo
  echo "Unable to update plugin installed in $GHIDRA_CONFIG! Has Ghidra not been run yet?"
fi

if [[ "$mode" != "build" ]]; then
  echo
  echo "Starting Ghidra with extension enabled in $mode mode..."
  echo

  "$INSTALL_DIR/support/launch.sh" $mode jdk Ghidra 4G "" ghidra.GhidraRun
fi
