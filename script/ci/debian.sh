#!/usr/bin/env bash

set -xe
export DEBIAN_FRONTEND=noninteractive

SUDO=''
if [[ $(id -u) -ne 0 ]]; then
    SUDO='sudo'
fi

$SUDO apt update

if $SUDO apt -qqy install temurin-21-jdk > /dev/null; then
   echo "Using Adoptium JDK 21";
elif $SUDO apt -qqy install openjdk-21 > /dev/null; then
  echo "Using OpenJDK 21";
else

  # We specifically need JDK 21 (it's required by Ghidra).
  # As it's not available in the repository first add Adoptium to the software sources
  $SUDO apt -qqy install wget apt-transport-https gpg > /dev/null
  wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor | tee /etc/apt/trusted.gpg.d/adoptium.gpg > /dev/null
  echo "deb https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list
  echo "Added packages.adoptium.net to the software sources"

  $SUDO apt update
  $SUDO apt -qqy install temurin-21-jdk > /dev/null
  echo "Using Adoptium JDK 21"
fi

$SUDO apt -qqy install unzip wget binutils gdb python3 > /dev/null

mkdir ghidra
pushd ghidra
  wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20250620.zip
  unzip -q ghidra_11.4_PUBLIC_20250620.zip
popd
