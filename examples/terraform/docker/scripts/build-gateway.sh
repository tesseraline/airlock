#!/bin/sh
# Builds the gateway image from the repository: locked requirements with hashes, the wheel, then the image.
#   build-gateway.sh TAG
set -eu
tag="${1:-airlock-gateway:local}"
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo"
uv export --no-dev --no-emit-project --format requirements-txt -q > docker/requirements.txt
rm -rf dist && uv build --wheel -q
docker build -q -f docker/Dockerfile -t "$tag" . >/dev/null
echo "built $tag"
