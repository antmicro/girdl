#!/usr/bin/env bash

export JAVA_HOME=$JAVA_HOME_21_X64
export PATH="$JAVA_HOME/bin":$PATH

set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export DATA="$(pwd)/src/test/resources"

function cleanup() {
  rm -rf ./standalone
}

cleanup
mkdir standalone

cp dist/girdl.zip standalone/girdl.zip
pushd standalone
unzip -q girdl.zip
set +x
time (

$SCRIPT_DIR/tests.py

);
echo
set -x
popd
cleanup
