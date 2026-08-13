# Manual-page Markdown

The files in `docs/man/` are the canonical authored manual-page sources.
They are also rendered directly into the versioned HTML documentation.

Pandoc 3.1 through 3.x derives deterministic roff into
`docs/man/generated/`. The generated roff is committed so ordinary builds and
installs do not require Pandoc.

Regenerate after changing a manual source:

```sh
ninja -C build update-man-pages
```

Qualification regenerates and byte-compares the committed derivative:

```sh
ninja -C build check-man-pages
```

`tools/canonicalize-man-roff.awk` normalizes presentation differences between
supported Pandoc 3.x writers. The Markdown remains the sole authored manual
authority; generated roff must never be edited directly.
