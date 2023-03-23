#!/usr/bin/env sh

set -e

./main.py 2>&1 | tee -a result.log