#!/bin/bash

echo "Installing Git Submodules..."
git submodule update --init --recursive

echo "Need to install 'unzip', 'python3-virtualenv', and 'openjdk-21-jdk' to run Bruteforce"
dpkg -s unzip &> /dev/null && echo "unzip already installed" || sudo apt install -y unzip
dpkg -s python3-virtualenv &> /dev/null && echo "python3-virtualenv already installed" || sudo apt install -y python3-virtualenv
dpkg -s openjdk-21-jdk &> /dev/null && echo "openjdk-21-jdk already installed"|| sudo apt install -y openjdk-21-jdk

if [ ! -d ~/ghidra_12.0_PUBLIC ]; then
    echo "Downloading Ghidra 12.0..."
    wget -P ~ https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0_build/ghidra_12.0_PUBLIC_20251205.zip
    unzip ~/ghidra_12.0_PUBLIC_20251205.zip -d ~/
    rm ~/ghidra_12.0_PUBLIC_20251205.zip
    echo "Ghidra 12.0 downloaded and extracted to ~/ghidra_12.0_PUBLIC"
else
    echo "Ghidra 12.0 already installed in ~/ghidra_12.0_PUBLIC"
fi

if [ -n "$GHIDRA_HOME" ]; then
    echo "Ghidra home already set to $GHIDRA_HOME"
else
    echo "Setting Ghidra home to ~/ghidra_12.0_PUBLIC..."
    export GHIDRA_HOME=~/ghidra_12.0_PUBLIC
    echo "export GHIDRA_HOME=~/ghidra_12.0_PUBLIC" >> ~/.bashrc
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

echo "You will need to run 'source .venv/bin/activate' to activate the virtual environment before running the scripts."
echo "all done!"
exit 0