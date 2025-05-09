#!/bin/bash
git submodule update --init --recursive
sudo apt install -y unzip openjdk-21-jdk
wget -P ~ https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
unzip ~/ghidra_11.3.2_PUBLIC_20250415.zip -d ~/
rm ~/ghidra_11.3.2_PUBLIC_20250415.zip
mkdir ~/ghidra_scripts
cp ghidra_scripts/* ~/ghidra_scripts/