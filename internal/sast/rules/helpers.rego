// SPDX-License-Identifier: Apache-2.0
// Helper functions and templates for SAST rules

package vulnetix.helpers

import rego.v1

// Common language detection functions
_is_lang(path, ext) if endswith(path, ext)

is_c(path) if endswith(path, ".c")
is_cpp(path) if endswith(path, ".cpp") or endswith(path, ".cc") or endswith(path, ".cxx")
is_c_like(path) if is_c(path) or is_cpp(path)

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
is_docker(path) if endswith(path, ".dockerfile") or endswith(path, ".docker")
is_bash(path) if endswith(path, ".sh")
is_gql(path) if endswith(path, ".graphql") or endswith(path, ".gql")
is_tf(path) if endswith(path, ".tf")
is_sql(path) if endswith(path, ".sql")

// Skip patterns for generated/minified files
_should_skip(path) if endswith(path, ".lock")
_should_skip(path) if endswith(path, ".sum")
_should_skip(path) if endswith(path, ".min.js")
_should_skip(path) if endswith(path, ".min.css")
_should_skip(path) if endswith(path, ".min.html")
_should_skip(path) if endswith(path, ".min.json")

// Common dangerous function patterns
_bash_injection_indicators = ["eval ", "$( ", "`", "| sh", "| bash"]
_sql_injection_indicators = ["SELECT * FROM", "INSERT INTO", "UPDATE ", "DELETE FROM",
  "WHERE ", "DROP ", "UNION SELECT", "OR 1=1", "' OR '", '" OR "']
_xss_indicators = ["innerHTML", "outerHTML", "document.write", "eval(",
  "setTimeout(", "setInterval("]

// CVSS base scores for severity mapping
_cvss_severity_map = {
  "HIGH": 7.0..10.0,
  "MEDIUM": 4.0..6.9,
  "LOW": 0.1..3.9,
}

// Generate standardized finding
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