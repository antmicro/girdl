#!/usr/bin/env bash

# Changing URL will change the version of ghidra used by the whole project
export GITHUB_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip"

force='0'

while getopts 'f' flag; do
  case "${flag}" in
    f) force='1' ;;
    *) echo "Usage: $0 [-f]"
       exit 1 ;;
  esac
done

if [[ "$force" == "0" ]]; then
  if [[ "$(cat ./ghidra/source.txt)" == "$GITHUB_URL" ]]; then
    echo "Ghidra already up-to-date, to force reinstall rerun with -f"
    exit 0
  fi
fi

rm -rf ./ghidra
mkdir ghidra
pushd ghidra >/dev/null || exit 1

  # Get filename from URL without the number at the end
  GHIDRA_RAW_NAME="$(basename "$GITHUB_URL" | cut -d_ -f1-3)"

  echo "Downloading Ghidra build from github..."
  wget -q "$GITHUB_URL" -O ghidra.zip

  echo "Unpacking Ghidra archive..."
  unzip -q ghidra.zip
  rm ghidra.zip

  if [[ -d "$GHIDRA_RAW_NAME" ]]; then
    mv "$GHIDRA_RAW_NAME" install
  else
    echo "Something went wrong! Can't find '$GHIDRA_RAW_NAME' in ./ghidra/ after unzipping!"
    exit 1
  fi

  echo "$GITHUB_URL" > source.txt
  echo "$GHIDRA_RAW_NAME" > config.txt

popd >/dev/null || exit 1

echo "Local Ghidra installation ready!"