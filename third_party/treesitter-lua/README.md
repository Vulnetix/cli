# treesitter-lua (vendored fork)

Local fork of `github.com/smacker/go-tree-sitter/lua` carrying a single
one-character source-only patch to `parser.c` line 254. The upstream
generated `ts_symbol_names[anon_sym_] = "<raw NUL byte>"` triggers a
GCC `null character(s) preserved in literal` warning that has no
specific `-W` flag to silence. Replacing the raw NUL with the `"\0"`
escape sequence produces byte-identical compiled output and silences
the warning without setting `CGO_CFLAGS=-w` globally.

The package is imported as `lua` and exposes `GetLanguage()` with the
same signature as upstream. Re-sync from upstream by recopying
`binding.go`, `parser.c`, `parser.h`, `scanner.c` and re-applying the
patch (`perl -i -pe 's/"\x00"/"\\0"/g' parser.c`).

Upstream license: MIT (see `LICENSE.upstream`).
