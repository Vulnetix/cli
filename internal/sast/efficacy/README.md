# SAST rule efficacy

A rule is effective when it reports the defect it was written for, in the
shapes that defect really takes, and stays quiet on code that only resembles
it. This directory holds the harness that measures both, and
`internal/sast/testdata/efficacy/` holds the cases.

## Cases

```
internal/sast/testdata/efficacy/<rule-stem>/<case-name>/<any files...>
```

- `<rule-stem>` is the rule file name without `.rego` (`vnx-go-014`, `vnx-89`).
- A case is a directory of real files at real relative paths. Paths matter:
  `Dockerfile`, `.github/workflows/ci.yml`, `src/app_test.go` and
  `templates/index.html` are what the rule sees.
- A line that begins with `~>` is a line the rule **must** report. The marker
  is removed before scanning, so `~>	db.Query(q)` scans as `	db.Query(q)`.
- Every other line **must not** be reported. A case with no marker is a pure
  false-positive trap.
- Name cases for what they prove: `tp-concat-in-exec`, `tp-two-line-taint`,
  `fp-parameterised-query`, `fp-in-comment`, `fp-test-file`. `tp-` cases have
  at least one marker, `fp-` cases have none.

Cases run through the production engine (`sast.NewEngine(...).Evaluate`), so
the input builder, gitignore handling, the language filter and the
per-finding file scope (`internal/sast/file_scope.go`) all apply as in a scan.

Never copy code from a third-party rule repository's tests into a case. Write
the code yourself.

### What a rule's case set must cover

1. **Every shape of the defect the rule claims.** The common one, a two-line
   form (source assigned on one line, sink on the next), every API the
   description names, every language in `metadata.languages`, and the
   formatting variants real code uses (extra spaces, line breaks inside a
   call, single and double quotes, aliases such as `import subprocess as sp`).
2. **The lookalikes.** The safe API next to the unsafe one (parameterised
   query, `yaml.safe_load`, `html/template`), the sanitised flow, the constant
   argument, the pattern inside a string literal or a comment, the pattern in
   a test file when the rule is about production hardening, documentation.
3. **The boundaries.** What the rule deliberately does not do (deep dataflow,
   cross-file flows) gets an `fp-` or a documented gap, not silence.

## Commands

Build once, then run from the repository root. Rules are read from disk, so
an edited rule is measured immediately without rebuilding.

```
go build -o /tmp/sasteff ./tools/sasteff

sasteff cases vnx-go-014 vnx-89          # run cases; prints FN/FP lines and recall/precision
sasteff cases -q                          # every case, failures only
sasteff coverage                          # rules missing a tp- or an fp- case
sasteff secrets                           # generated secret rules vs their own token shapes
sasteff snapshot -out c.json DIR...       # freeze a corpus
sasteff hits -snapshot c.json vnx-89      # what the rule reports on real code
sasteff perf -snapshot c.json [stem...]   # per-rule eval and compile cost
sasteff total -kind sast DIR...           # full-ruleset wall time through the engine
```

`hits` on a corpus of ordinary, well-maintained projects is the precision
check that cases cannot be: most of what a rule reports there is noise. On a
corpus of deliberately vulnerable applications it is the recall check.

## Writing a rule that works

- **Match a call, not a word.** Anchor on the API (`hashlib.md5(`,
  `\.Query\(` with a receiver), on a declaration, or on an assignment to a
  name that says what it is.
- **Take the sink, then ask whether the source reaches it.** Reading a request
  parameter is not a finding; passing it to a command, a query or a file path
  is. `helpers.tainted_names(lines, i, before, source_re)` returns variables
  assigned from `source_re` in the lines above `i`; `helpers.assigned_first`
  takes the first name on the left of an assignment (`n, err := ...` is `n`).
  Check the lines between for a guard or sanitiser.
- **Code, not prose.** `helpers.is_comment_line`, `helpers.code_window` and
  `helpers.next_code_index` skip comments. The engine already drops a `sast`
  finding whose line is only a comment, and any finding in Markdown or Rego,
  unless the rule is tagged `comments` or `documentation`.
- **Stay in your language.** Gate on file extension. A rule that declares
  `languages` never reports a file of a different known language.
- **A mitigation elsewhere counts.** Middleware, a project-wide limiter or a
  framework default protects every handler; hardening rules judge the project
  and skip `helpers.is_test_path`.
- **Describe exactly what is matched.** `metadata.description` says what the
  rule reports and what it deliberately does not. "Detects source patterns
  associated with CWE-N" is not a description.

## Performance

Every rule is evaluated against every file. A rule that splits every file
into lines and tests every line pays for the whole repository, so gate on the
whole file first:

```rego
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "subprocess")          # one check per file
	lines := split(content, "\n")             # only files that can match
	some i, line in lines
	...
}
```

A regular expression can gate a whole file in multi-line mode
(`regex.match(concat("", ["(?m)", pattern]), content)`) whenever it would match a line of
it. Prefer `some path, content in input.file_contents` to
`some path in object.keys(...)` followed by a lookup. `sasteff perf` shows
outliers.

## Credentials in cases

Never write a token in a live provider format into a case: it trips push
protection and is a leak-shaped artefact. Write the shape instead, and the
loader fills it at test time with a random string the expression matches:

```
~>aws_secret_access_key = "@@sample:[A-Za-z0-9/+=]{40}@@"
~>token: @@sample:ghp_[A-Za-z0-9]{36}@@
```

Placeholder values ("your-key-here", "xxxxxxxx…") are fine to write literally
in `fp-` cases.
