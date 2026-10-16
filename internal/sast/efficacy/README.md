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

## Known limits

These are the gaps that were measured and left open, each with its cause. A rule
that meets one is not broken; the shape is outside what a rule reading one
project's files line by line can decide. Anything a rule cannot resolve stays
reported, so a limit costs a false positive, not a missed finding, unless
stated otherwise.

Measured against the OWASP Benchmark (Java 1.2 and Python 0.1) and Juice Shop's
own `vuln-code-snippet` labels (`sasteff bench` for the Benchmark; for Juice
Shop, compare each `vuln-code-snippet vuln-line` comment with the lines
`sasteff hits` reports, same line or adjacent):

| Area | Limit | Why |
|---|---|---|
| Python XPath, command injection (VNX-643, VNX-PY-007) | 7 false positives, all `request.path.split("/")[1]` or a request wrapper whose method is only *named* "safe" | A path segment is constant only because of the route definition, and a method name proves nothing about its body |
| Java XPath (VNX-643) | its 15 request-traced Java findings are reported by VNX-JAVA-013 | one defect, one finding: the pair was deduplicated on purpose |
| Weak hash (VNX-CRYPTO-001, VNX-CRYPTO-002) | an algorithm named only in a gitignored properties file is not seen | the scan skips files the project ignores; with the file visible the Benchmark scores 129 of 129 |
| Cross-file Java calls | one level deep, methods over 60 lines, varargs, lambdas, a receiver held in a field | the summary is a bounded line-level reading; anything it cannot resolve stays tainted |
| A field assigned from outside its class | `new Cls().getter()` is read as constant | the inert-call fallback cannot see the assignment; a real flow through such a class can be missed |
| Language pre-filter | a rule is dropped when none of its declared languages is in the project | an XML-only, YAML-only or properties-only tree reports nothing for rules that declare only code languages; the docs of VNX-431, VNX-936, VNX-1395 and VNX-ANDROID-005 say so |
| Juice Shop labelled lines | 11 of 36 reported | the rest are data (security-question answers, allowlist entries), an absent guard (a route with no `canActivate`), a hidden-feature route, a runtime-computed matcher, Solidity, or a route that is unauthenticated only by deployment |
| Juice Shop "correct" fixes | 5 of 25 still flagged | each still contains the weakness the rule names (a bypassable `includes` allowlist, `multi: true` with a request-chosen id); they are findings in code the project calls fixed |

The independent `ind-*` cases are the check that does not depend on the agents
that fixed a rule: a writer who saw only the rule's doc page wrote them. Before
repair 219 of 3,968 documented positives were missed and 123 of 3,646
documented negatives were reported; after repair none is. When a doc and a rule
disagree, change the rule or narrow the doc, then keep a case for the claim that
remains.
