#!/usr/bin/env bash
# Validate every GitLab CI example against GitLab's own JSON schema.
#
#   bash examples/gitlab/validate.sh
#
# Two things stop check-jsonschema reading these files directly:
#
#   1. Component templates are two-document YAML (a `spec:` header, then the
#      config). check-jsonschema cannot parse a multi-document stream.
#   2. `!reference [.job, key]` is a GitLab-specific YAML tag that no generic
#      YAML parser can construct.
#
# So each file is normalised into a temp copy first: the `spec` header is
# split off and checked on its own, and `!reference` tags are flattened to
# strings (which is what the schema expects at those positions anyway).
#
# This catches unknown keywords, wrong types, and bad enums. It does NOT catch
# a `needs:` pointing at a job that does not exist, or an `include:` that
# resolves to nothing. For that, use the CI Lint API against a real project —
# see "Verifying These Examples" in the docs.

set -euo pipefail

cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== Normalising"
uv run --quiet --with pyyaml python - "$tmp" <<'PY'
import pathlib, sys, yaml

out_dir = pathlib.Path(sys.argv[1])

class GitLabLoader(yaml.SafeLoader):
    """SafeLoader that understands GitLab's !reference tag."""

def _reference(loader, node):
    # !reference [.job, before_script] -> a plain string placeholder.
    parts = loader.construct_sequence(node)
    return "!reference [" + ", ".join(str(p) for p in parts) + "]"

GitLabLoader.add_constructor("!reference", _reference)

SPEC_INPUT_KEYS = {"default", "description", "type", "options", "regex"}
failures = []

for src in sorted(pathlib.Path(".").glob("**/*.yml")):
    if src.is_relative_to(out_dir):
        continue
    docs = list(yaml.load_all(src.read_text(), Loader=GitLabLoader))
    is_component = src.parent.name == "templates" and src.parts[0] == "component"

    if is_component:
        if len(docs) != 2:
            failures.append(f"{src}: expected 2 YAML documents, got {len(docs)}")
            continue
        spec, config = docs
        if "spec" not in spec or "inputs" not in (spec.get("spec") or {}):
            failures.append(f"{src}: first document must be a spec header with inputs")
            continue
        for name, meta in (spec["spec"]["inputs"] or {}).items():
            extra = set(meta or {}) - SPEC_INPUT_KEYS
            if extra:
                failures.append(f"{src}: input {name!r} has unknown keys {sorted(extra)}")
        if not isinstance(config, dict) or not config:
            failures.append(f"{src}: second document must define jobs")
            continue
    else:
        if len(docs) != 1:
            failures.append(f"{src}: expected a single YAML document, got {len(docs)}")
            continue
        config = docs[0]

    dst = out_dir / str(src).replace("/", "__")
    dst.write_text(yaml.safe_dump(config, sort_keys=False))

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
PY

echo
echo "== Schema"
check-jsonschema --builtin-schema vendor.gitlab-ci "$tmp"/*.yml

echo
echo "All GitLab examples validate."
