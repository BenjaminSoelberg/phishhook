#!/usr/bin/env sh

set -e

BUILD_KIT=1 docker build -t phishhook .
docker run --rm -it phishhook
