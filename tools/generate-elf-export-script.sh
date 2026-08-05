#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

manifest=$1

awk '
function fail(message)
{
  print "generate-elf-export-script: " message > "/dev/stderr"
  exit 1
}

BEGIN {
  print "{"
  print "  global:"
}

/^[[:space:]]*($|#)/ {
  next
}

{
  if ($0 !~ /^_Z[A-Za-z0-9_]+$/) {
    fail("invalid symbol on line " NR ": " $0)
  }
  if (seen[$0]++) {
    fail("duplicate symbol on line " NR ": " $0)
  }
  print "    " $0 ";"
  count++
}

END {
  if (count == 0) {
    fail("manifest contains no symbols")
  }
  print "  local:"
  print "    *;"
  print "};"
}
' "$manifest"
