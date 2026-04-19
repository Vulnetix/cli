# SPDX-License-Identifier: Apache-2.0
# Helper functions and templates for SAST rules

package vulnetix.helpers

import rego.v1

# Common language detection functions
_is_lang(path, ext) if endswith(path, ext)

is_c(path) if endswith(path, ".c")

is_cpp(path) if endswith(path, ".cpp")
is_cpp(path) if endswith(path, ".cc")
is_cpp(path) if endswith(path, ".cxx")

is_c_like(path) if is_c(path)
is_c_like(path) if is_cpp(path)

is_go(path) if endswith(path, ".go")
is_java(path) if endswith(path, ".java")
is_js(path) if endswith(path, ".js")
is_ts(path) if endswith(path, ".ts")
is_py(path) if endswith(path, ".py")
is_ruby(path) if endswith(path, ".rb")
is_php(path) if endswith(path, ".php")
is_rust(path) if endswith(path, ".rs")
is_swift(path) if endswith(path, ".swift")
is_kotlin(path) if endswith(path, ".kt")
is_docker(path) if endswith(path, ".dockerfile")
is_docker(path) if endswith(path, ".docker")

is_bash(path) if endswith(path, ".sh")

is_gql(path) if endswith(path, ".graphql")
is_gql(path) if endswith(path, ".gql")
is_tf(path) if endswith(path, ".tf")
is_sql(path) if endswith(path, ".sql")

# Skip patterns for generated/minified files
_should_skip(path) if endswith(path, ".lock")
_should_skip(path) if endswith(path, ".sum")
_should_skip(path) if endswith(path, ".min.js")
_should_skip(path) if endswith(path, ".min.css")
_should_skip(path) if endswith(path, ".min.html")
_should_skip(path) if endswith(path, ".min.json")

# Note: Pattern indicators are checked inline in rules using contains()
# CVSS base scores are mapped inline in rules

# Generate standardized finding
generate_finding(severity, level, rule_id, message, artifact_uri, start_line, snippet) = finding {
  finding := {
    "rule_id": rule_id,
    "message": message,
    "artifact_uri": artifact_uri,
    "severity": severity,
    "level": level,
    "start_line": start_line,
    "snippet": snippet,
  }
}