#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 3 ] || {
  echo 'usage: qualify-html-docs.sh BUILD-DIR PROJECT VERSION' >&2
  exit 2
}
build=$1
project=$2
version=$3
if [ -s "$build/ci-install-prefix" ]; then
  prefix=$(cat "$build/ci-install-prefix")
else
  prefix=$build/install
fi
root=$prefix/share/htmldocs/$project/$version
python3 tools/check-html-docs.py "$root" \
  --manifest docs/html-manifest.json \
  --forbid-path "$GITHUB_WORKSPACE" \
  --forbid-path "$build"
