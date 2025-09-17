#!/usr/bin/env bash

set -xe
export GHIDRA_INSTALL_DIR="$(pwd)/ghidra/ghidra_11.4_PUBLIC"
export JAVA_HOME=$JAVA_HOME_21_X64
export PATH=$JAVA_HOME:$PATH
./gradlew $@