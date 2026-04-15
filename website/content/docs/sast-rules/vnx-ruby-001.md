---
title: "VNX-RUBY-001 – Missing Gemfile.lock"
description: "Detect Ruby projects that have a Gemfile but no Gemfile.lock, leaving dependencies unpinned and vulnerable to non-deterministic resolution and supply chain attacks."
---

## Overview

This rule flags Ruby projects that have a `Gemfile` but no corresponding `Gemfile.lock`. The `Gemfile.lock` records the exact resolved version of every gem in the dependency graph — direct and transitive — at the time `bundle install` was last run. Without it, running `bundle install` on a fresh checkout resolves version constraints fresh from RubyGems.org, meaning two builds from the same source tree can install entirely different code depending on what was published between the two runs. This maps to [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html).

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Without a `Gemfile.lock`, a dependency confusion attack, a compromised gem maintainer account, or a typosquat package on RubyGems.org can silently inject malicious code into your build. The substituted gem arrives as a legitimately resolved version that satisfies your floating constraint (e.g., `gem 'rails', '~> 7.0'`). Neither the developer nor the CI system sees anything unusual — the build completes successfully with malicious code included.

In CI/CD pipelines, where `bundle install` runs on every push, this attack is repeatable. A poisoned gem can steal environment variables, install a web shell, or silently modify application logic. MITRE ATT&CK technique T1195.001 (Supply Chain Compromise: Compromise Software Dependencies) documents this attack class.

The `Gemfile.lock` also enables `bundle exec`, which runs commands using exactly the gem versions recorded in the lock file, preventing version skew between local development and production environments.

## What Gets Flagged

The rule fires when a directory is registered as containing Ruby source files but the file `Gemfile.lock` is absent from that same directory.

```ruby
# FLAGGED: project directory has Gemfile but no Gemfile.lock
# $ ls
# Gemfile   app/   lib/
# (Gemfile.lock is missing — gems are not pinned)
```

## Remediation

1. **Generate the lock file.** Run `bundle install` in the directory containing your `Gemfile`. This resolves the full dependency graph and writes `Gemfile.lock`.

```bash
bundle install
```

2. **Commit `Gemfile.lock` to version control.** The file must be present in source control so every developer, CI build, and deployment environment uses the identical set of resolved gem versions.

```bash
git add Gemfile.lock
git commit -m "chore: add Gemfile.lock to pin gem versions"
```

3. **Use `bundle exec` for all commands.** Running commands through `bundle exec` ensures they run with exactly the gem versions recorded in the lock file, not whatever happens to be installed system-wide:

```bash
# SAFE: locked execution — uses exactly the versions in Gemfile.lock
bundle exec rails server
bundle exec rspec
bundle exec rake db:migrate
```

4. **Verify the lock file in CI before installing.** Add a step that confirms the lock file is consistent with the current `Gemfile` before proceeding with the build:

```bash
# SAFE: verify Gemfile.lock is up to date before installing
bundle check || bundle install
```

5. **For production deployments, install without development and test gems.** This reduces the installed surface area and skips gems that are only needed for testing:

```bash
# SAFE: production install — locked versions, no dev/test gems
bundle install --without development test
```

6. **Prevent accidental exclusion.** Ensure `Gemfile.lock` is not listed in `.gitignore`. For application repositories, the lock file should always be committed. For gem libraries (packages you publish to RubyGems), it is conventional to `.gitignore` the lock file for the library itself — but this applies only to the published package, not to your library's own CI test environment.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [Bundler documentation – Gemfile.lock](https://bundler.io/guides/rationale.html)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
