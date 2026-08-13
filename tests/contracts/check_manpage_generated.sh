#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
pandoc=$2
exec "$root/tools/update-man-pages.sh" --check "$pandoc" "$root"
