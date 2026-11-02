---
title: "VNX-RUBY-009 – Dynamic Method Dispatch via send with User-Controlled Method Name"
description: "Reports send, public_send, __send__ and try calls whose method name comes from params, request or cookies data, directly or through a variable assigned nearby, unless an allowlist check guards it."
---

## Overview

This rule flags calls to `send`, `public_send`, or `__send__` in Ruby files where the first argument — the method name — is sourced from `params` or `request` objects. Ruby's `send` family of methods performs dynamic method dispatch: at runtime the interpreter looks up the named method on the receiver and calls it. When the method name comes from user input, an attacker can call any method accessible on the receiver, including ones never intended for external use.

The danger is compounded by the breadth of methods available on common Rails objects. An attacker targeting an ActiveRecord model can call `destroy`, `delete_all`, `update_all`, or `connection.execute`. Targeting a controller, they might invoke `redirect_to` with an arbitrary URL, `render file:` with a path of their choice, or `send_file` to exfiltrate server files. The full attack surface depends on the receiver type, but in all cases the application logic is completely bypassed.

This rule corresponds to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** High | **CWE:** [CWE-94 – Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

Dynamic dispatch via `send` is a powerful metaprogramming feature that Rails and Ruby libraries use extensively for legitimate purposes — for example, routing DSLs and attribute accessors. When developers carry this pattern into controller or model code while accepting the method name from user input, they inadvertently expose the entire Ruby object graph to the internet.

A realistic attack scenario: a REST API accepts a JSON body containing `{"action": "destroy"}` and routes it to `model.send(params[:action])`. The developer intended only `activate` and `deactivate` to be valid actions, but never enforced this. An attacker sends `destroy` and deletes the record. Sending `class` returns the class name, which combined with further calls can probe the application. Sending `system` with a second argument can spawn OS processes if the receiver is a class that responds to it.

Even `public_send` — which restricts dispatch to public methods — provides a much larger attack surface than developers typically realise. Protecting against this class of vulnerability requires treating the method name as untrusted data and validating it against a fixed allowlist before any dispatch occurs.

## What Gets Flagged

The rule reports a `send`, `public_send`, `__send__` (with or without a receiver or parentheses) or `try` call in a `.rb` file whose first argument, the method name, comes from `params`, `request.params`/`query_parameters`/`headers` or `cookies`: directly, inside an interpolated or concatenated string, or through a variable assigned from that input within the 15 lines above.

```ruby
# FLAGGED: method name sourced from params
@widget.send(params[:operation])
widget.__send__ params[:other]

# FLAGGED: two-line flow; respond_to? is not a guard
name = params[:probe]
result = HealthProbe.new.send(name) if HealthProbe.new.respond_to?(name)

# FLAGGED: name built from input
profile.send("#{params[:field]}=", params[:value])
```

Not flagged: a symbol method name with input only in later arguments (`send(:update, params[:account])`), a name checked by `ALLOWED.include?(name)` (or `in?`, `==`) above or on the same line, a constant-table lookup (`FORMATS.fetch(params[:format])`), `send_file`/`send_data`, `socket.send(data, 0)`, comments and string literals.

## Remediation

1. **Validate the method name against an explicit allowlist before dispatching.** This is the safest approach — the method called is always one of a known finite set:

```ruby
# SAFE: allowlist validation before dynamic dispatch
ALLOWED_ACTIONS = %w[activate deactivate archive].freeze

action = params[:action]
unless ALLOWED_ACTIONS.include?(action)
  render json: { error: "Unknown action" }, status: :bad_request
  return
end
@resource.public_send(action)
```

2. **Replace dynamic dispatch with a case/when statement.** When the number of valid methods is small, explicit branching is clearer and eliminates any possibility of unintended dispatch:

```ruby
# SAFE: explicit branching — no dynamic dispatch
case params[:action]
when "activate"   then @resource.activate
when "deactivate" then @resource.deactivate
else render json: { error: "Unknown action" }, status: :unprocessable_entity
end
```

3. **Use a command object or service pattern.** Map external identifiers to callable objects rather than method names, completely decoupling the public interface from internal Ruby methods:

```ruby
# SAFE: map to command objects, not method names
COMMANDS = {
  "activate"   => ->(r) { r.activate },
  "deactivate" => ->(r) { r.deactivate },
}.freeze

cmd = COMMANDS[params[:action]]
return render json: { error: "Unknown action" }, status: :bad_request unless cmd
cmd.call(@resource)
```

## References

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
- [OWASP Ruby on Rails Security Guide – Mass Assignment](https://guides.rubyonrails.org/security.html#mass-assignment)
- [Ruby Object#send documentation](https://ruby-doc.org/core/Object.html#method-i-send)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
