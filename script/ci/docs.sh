#!/usr/bin/env bash

set -xe

SUDO=''
if [[ $(id -u) -ne 0 ]]; then
    SUDO='sudo'
fi

$SUDO apt -qqy install python3-venv python3-pip > /dev/null
python3 -m venv .venv/
source .venv/bin/activate

pushd docs
  pip3 install -q -r requirements.txt
  make html
  tar cf docs.tar -C build/html/ .
popd