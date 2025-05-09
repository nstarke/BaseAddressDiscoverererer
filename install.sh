#!/bin/bash

echo "Installing Git Submodules..."
git submodule update --init --recursive

echo "Need to install 'unzip', 'python3-virtualenv', and 'openjdk-21-jdk' to run Bruteforce"
dpkg -s unzip &> /dev/null && echo "unzip already installed" || sudo apt install -y unzip
dpkg -s python3-virtualenv &> /dev/null && echo "python3-virtualenv already installed" || sudo apt install -y python3-virtualenv
dpkg -s openjdk-21-jdk &> /dev/null && echo "openjdk-21-jdk already installed"|| sudo apt install -y openjdk-21-jdk

if [ ! -d ~/ghidra_11.3.2_PUBLIC ]; then
    echo "Downloading Ghidra 11.3.2..."
    wget -P ~ https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
    unzip ~/ghidra_11.3.2_PUBLIC_20250415.zip -d ~/
    rm ~/ghidra_11.3.2_PUBLIC_20250415.zip
    echo "Ghidra 11.3.2 downloaded and extracted to ~/ghidra_11.3.2_PUBLIC"
else
    echo "Ghidra 11.3.2 already installed in ~/ghidra_11.3.2_PUBLIC"
fi

if [ -n "$GHIDRA_HOME" ]; then
    echo "Ghidra home already set to $GHIDRA_HOME"
else
    echo "Setting Ghidra home to ~/ghidra_11.3.2_PUBLIC..."
    export GHIDRA_HOME=~/ghidra_11.3.2_PUBLIC
    echo "export GHIDRA_HOME=~/ghidra_11.3.2_PUBLIC" >> ~/.bashrc
    source ~/.bashrc
fi

if [ ! -d ~/ghidra_scripts ]; then
    echo "Creating ~/ghidra_scripts directory..."
    mkdir ~/ghidra_scripts
else
    echo "~/ghidra_scripts directory already exists"
fi

echo "Copying scripts to ~/ghidra_scripts..."
cp ghidra_scripts/* ~/ghidra_scripts/

if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    virtualenv .venv
else
    echo "Virtual environment already exists"
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing requirements..."
pip install -r requirements.txt

echo "all done!"
exit 0