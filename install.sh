#!/bin/bash

git submodule update --init --recursive

echo "Need to install 'unzip' and 'openjdk-21-jdk' to run Ghidra"
dpkg -s unzip &> /dev/null || sudo apt install -y unzip
dpkg -s openjdk-21-jdk &> /dev/null || sudo apt install -y openjdk-21-jdk

if [ ! -d ~/ghidra_11.3.2_PUBLIC ]; then
    wget -P ~ https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
    unzip ~/ghidra_11.3.2_PUBLIC_20250415.zip -d ~/
    rm ~/ghidra_11.3.2_PUBLIC_20250415.zip
fi

if [ ! -d ~/ghidra_scripts ]; then
    mkdir ~/ghidra_scripts
fi

cp ghidra_scripts/* ~/ghidra_scripts/