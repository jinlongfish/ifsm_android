#!/usr/bin/env bash
set -euo pipefail
python -m pip install --upgrade pip setuptools wheel
pip install "cython==0.29.*" buildozer
buildozer android debug
echo "APK build complete. Check the bin/ directory."
