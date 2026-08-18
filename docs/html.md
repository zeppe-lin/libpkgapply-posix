# HTML documentation

The `html_docs` Meson feature builds a versioned static documentation tree for
libpkgapply-posix. The tree is generated from the repository's authoritative Markdown,
canonical Markdown manual sources, public headers, legal notices, and
Doxygen configuration.

Generation is atomic. The checker rejects missing inventory entries, broken or
escaping local links, leaked source/build paths, and source-format links. The
installed tree is placed below:

```
share/htmldocs/libpkgapply-posix/3.2.2
```

HTML output is derived. Edit the Markdown, headers, or Doxygen source and
regenerate; never patch generated HTML.
