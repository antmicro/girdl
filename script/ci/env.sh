#!/usr/bin/env bash

set -xe

if [ -z "$GHIDRA_INSTALL_DIR" ]; then
  export GHIDRA_INSTALL_DIR="$(pwd)/ghidra/ghidra_11.4_PUBLIC"
fi

export JAVA_HOME=$JAVA_HOME_21_X64
export PATH=$JAVA_HOME:$PATH