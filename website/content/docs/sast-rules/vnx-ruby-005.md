---
title: "VNX-RUBY-005 – Ruby XSS via html_safe or raw"
description: "Detect use of .html_safe and raw() in Rails views and helpers, which bypass Rails' automatic HTML escaping and can introduce cross-site scripting (XSS) vulnerabilities when applied to user-controlled strings."
---

## Overview

This rule flags uses of `.html_safe` and `raw()` in Ruby source files and Rails templates. Rails automatically HTML-escapes string values inserted into view templates with `<%= %>`. Calling `.html_safe` on a string marks it as trusted, and `raw()` is an alias that does the same thing — both bypass the automatic escaping. When applied to strings that contain user-controlled content, this directly enables cross-site scripting (XSS). This maps to [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

Cross-site scripting allows an attacker to inject JavaScript that runs in the browser of any user who views the page. In a Rails application, stored XSS (where the injected content is saved to the database and served to other users) is the most impactful variant: a single injected payload can steal session cookies, capture keystrokes, exfiltrate form values, redirect users to phishing pages, or perform actions on the user's behalf (CSRF via XSS).

Because Rails escapes by default, `.html_safe` is by design an escape hatch — and it is often added by developers who want to render HTML content they generated themselves, such as links, formatted dates, or localized strings containing HTML tags. The problem arises when the "trusted" string has been contaminated by a user-supplied value somewhere in its construction chain. A helper method that builds an HTML snippet with `.html_safe` at the end is safe only if every input to that snippet is also escaped; one unescaped interpolation anywhere in the chain produces XSS.

## What Gets Flagged

The rule matches any file (including `.erb`, `.haml`, `.rb`) that contains `.html_safe` or a `<%= raw ` expression.

```ruby
# FLAGGED: user attribute marked as html_safe — direct XSS if name contains HTML
@user.name.html_safe

# FLAGGED: raw() in ERB template with user data
<%= raw @comment.body %>

# FLAGGED: html_safe on an interpolated string containing user data
"Hello, #{current_user.name}!".html_safe

# FLAGGED: html_safe in a helper that processes user content
def format_bio(user)
  user.bio.gsub("\n", "<br>").html_safe
end

# FLAGGED: html_safe on a string built from params
link = "<a href='#{params[:url]}'>click</a>".html_safe
```

## Remediation

1. **Let Rails escape output automatically.** The default `<%= expression %>` in ERB calls `html_escape()` on any non-`html_safe` string. Simply removing `.html_safe` or `raw()` restores this protection:

```erb
<%# SAFE: Rails escapes @comment.body automatically %>
<%= @comment.body %>
```

2. **Use `sanitize()` when you need to allow a subset of HTML tags.** The `ActionView::Helpers::SanitizeHelper#sanitize` method strips all HTML tags except for an explicit allowlist, and escapes all attributes except those explicitly permitted. This is the correct approach for rich-text content stored in the database:

```erb
<%# SAFE: allow only specific tags — scripts and event handlers are stripped %>
<%= sanitize @comment.body, tags: %w[b i em strong br p a], attributes: %w[href class] %>
```

3. **Use `content_tag()` and Rails view helpers to construct HTML programmatically.** `content_tag()` and `link_to()` automatically escape their string arguments, so you never need `.html_safe` when using them correctly:

```ruby
# SAFE: content_tag escapes the content automatically
content_tag(:p, current_user.bio)

# SAFE: link_to escapes the link text and validates href
link_to current_user.name, profile_path(current_user)
```

4. **When `.html_safe` is genuinely needed** — for example, when a helper constructs HTML from multiple components — ensure every variable interpolation is individually escaped before the final string is marked safe:

```ruby
# SAFE: each user-supplied component is escaped individually before the
#       final string is marked html_safe
def user_badge(user)
  name  = html_escape(user.display_name)
  role  = html_escape(user.role)
  "<span class=\"badge badge-#{html_escape(user.role_slug)}\">#{name} (#{role})</span>".html_safe
end
```

5. **Use `html_escape()` / `ERB::Util.html_escape()` explicitly** when building HTML strings in Ruby code (not in templates) that will be marked safe:

```ruby
# SAFE: explicit escaping before html_safe
safe_html = ERB::Util.html_escape(user_supplied_string)
result = "<div class=\"content\">#{safe_html}</div>".html_safe
```

6. **Review all uses of `.html_safe` in helpers and models.** A grep for `.html_safe` in your codebase shows every location where automatic escaping has been bypassed. Each occurrence should be reviewed to confirm that no user-controlled string reaches it without being escaped first.

```bash
grep -rn "\.html_safe\|<%= raw " app/ --include="*.rb" --include="*.erb"
```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS – Stored](https://capec.mitre.org/data/definitions/86.html)
- [Rails Security Guide – Cross-Site Scripting (XSS)](https://guides.rubyonrails.org/security.html#cross-site-scripting-xss)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Rails API – sanitize helper](https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html)
- [brakeman – Rails XSS detection](https://brakemanscanner.org/docs/warning_types/cross_site_scripting/)
