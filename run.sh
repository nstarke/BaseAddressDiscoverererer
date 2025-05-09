#!/bin/bash
FILENAME="$1"
if [ -z "$FILENAME" ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

bash install.sh
source .venv/bin/activate
source ~/.bashrc
python BruteForceAddress.py "$FILENAME"