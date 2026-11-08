#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Reproducible frontend build.
#
# The `dist/` tree committed in this repo must match the output of this script
# with the exact Node + lockfile the repo pins. Developers rebuild on their
# box; install.sh then ships the committed dist (so operators do NOT need
# Node on the box).
#
# Usage:  bash dashboard/frontend/build.sh
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
command -v npm >/dev/null 2>&1 || { echo "npm not found; install Node first." >&2; exit 2; }
if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi
npm run build
echo
echo "Built: $HERE/dist"
