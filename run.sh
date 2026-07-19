#!/bin/bash
set -e
cd "$(dirname "$0")"
if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi
source .venv/bin/activate
python3 run.py
