# Canonicalize semantically equivalent Pandoc man-writer output.
#
# Pandoc 3.x releases differ in presentation details that are not part of this
# project's manual-page contract: syntax-highlighting escapes may appear inside
# .EX/.EE blocks, and special characters may use either historical two-byte
# names such as \(bu or long names such as \[bu]. Normalize both classes before
# comparing or committing generated roff.

function normalize_two_character_escapes(line, before, name, after) {
  while (match(line, /\\\([^[:space:]][^[:space:]]/)) {
    before = substr(line, 1, RSTART - 1)
    name = substr(line, RSTART + 2, 2)
    after = substr(line, RSTART + RLENGTH)
    line = before "\\[" name "]" after
  }

  return line
}

/^\.EX$/ {
  in_example = 1
  print
  next
}

/^\.EE$/ {
  in_example = 0
  print
  next
}

{
  line = $0

  if (in_example) {
    gsub(/\\f\[[^]]+\]/, "", line)
  }

  line = normalize_two_character_escapes(line)
  print line
}
