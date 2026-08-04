# Code style

C++17 is required. Format C++ with clang-format 17 using the repository file.
Use two-space indentation, no tabs, explicit ownership, `[[nodiscard]]` on
fallible value-producing operations, and typed error categories carrying the
relevant system error and diagnostic path.

POSIX calls must be descriptor-anchored where authority outlives one expression.
Do not replace an exact failure with a boolean, silently follow a final symlink,
or infer semantic authority from a pathname.
