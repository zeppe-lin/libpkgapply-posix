# Manual-page Markdown

The files in `docs/man/` are deterministic Markdown mirrors of the canonical
scdoc sources in `man/`. They exist for static HTML generation and source-tree
reading. They are not an independent editing surface.

After changing a manual, regenerate its mirror with:

```sh
python3 tools/render-man-markdown.py \
  man/NAME.scdoc docs/man/NAME.md \
  --project libpkgapply-posix --version 3.2.0
```

`tools/check-man-markdown.py` rejects missing, extra, or stale mirrors.
