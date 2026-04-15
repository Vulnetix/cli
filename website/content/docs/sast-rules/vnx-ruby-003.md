---
title: "VNX-RUBY-003 – Insecure Deserialization in Ruby"
description: "Detect use of Marshal.load(), Marshal.restore(), YAML.load(), and YAML.unsafe_load() in Ruby source files, which can execute arbitrary code when deserializing attacker-controlled data."
---

## Overview

This rule flags calls to `Marshal.load()`, `Marshal.restore()`, `YAML.load()`, and `YAML.unsafe_load()` in Ruby source files. Both Marshal and the unsafe YAML loading functions can instantiate arbitrary Ruby objects and execute code during deserialization. When the serialized data comes from an attacker-controlled source — a cookie, an API payload, a message queue, a database field that users can influence — deserialization becomes a remote code execution primitive. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Ruby's Marshal format is a binary serialization of the complete Ruby object graph, including class references. When Marshal deserializes data, it allocates objects and calls their `initialize` and custom deserialization hooks. An attacker who can supply arbitrary Marshal data can trigger the execution of any method in any class loaded in the Ruby process, by constructing an object graph that chains together gadgets — objects whose normal lifecycle methods (like `to_s`, `respond_to_missing?`, or `marshal_load`) perform dangerous operations.

The Ruby on Rails framework has historically been vulnerable to deserialization via cookies (Rails stores session data in a signed cookie that used Marshal in older versions) and via `YAML.load()` calls in configuration and parameter parsing. CVE-2013-0156 (Rails YAML remote code execution, CVSS 10.0) and multiple subsequent CVEs demonstrate that this is not theoretical — production Rails applications have been compromised at scale via this vector.

`YAML.load()` in Ruby's Psych library (prior to Psych 4, released with Ruby 3.1) deserializes arbitrary Ruby objects by default because YAML has a type tag system that maps to Ruby class names. `YAML.unsafe_load()` explicitly opts back into this behavior on Psych 4+.

## What Gets Flagged

The rule matches `.rb` files containing any of the four dangerous deserialization calls.

```ruby
# FLAGGED: Marshal.load on data from any source
data = Marshal.load(params[:payload])

# FLAGGED: Marshal.restore (alias for Marshal.load)
obj = Marshal.restore(Base64.decode64(cookie_value))

# FLAGGED: YAML.load without safe class restrictions (Psych < 4 default)
config = YAML.load(request.body.read)

# FLAGGED: YAML.unsafe_load explicitly opts into object instantiation
YAML.unsafe_load(File.read('user_supplied_config.yml'))
```

## Remediation

1. **Use `JSON.parse()` for data exchange formats.** JSON cannot represent Ruby objects or trigger method calls — it deserializes to hashes, arrays, strings, and numbers only. For any data that crosses a trust boundary (HTTP requests, message queues, cookies, API responses), use JSON:

```ruby
# SAFE: JSON parsing — no object instantiation
require 'json'

data = JSON.parse(request.body.read, symbolize_names: false)
# Returns Hash/Array/String/Integer/Float/nil/true/false only
```

2. **Use `YAML.safe_load()` for YAML input.** `YAML.safe_load()` (the default behavior in Psych 4 / Ruby 3.1+) only deserializes basic types (strings, integers, floats, booleans, arrays, hashes) and raises a `Psych::DisallowedClass` exception if the YAML contains a type tag that maps to a Ruby class:

```ruby
# SAFE: YAML.safe_load restricts deserialized types
require 'yaml'

config = YAML.safe_load(yaml_string)
# Raises Psych::DisallowedClass if object tags are present

# SAFE: on Psych 4+, YAML.load() is safe by default
# On older Psych, explicitly use safe_load
```

3. **If you need to deserialize specific custom classes with YAML, pass `permitted_classes:`** rather than using `unsafe_load`. This restricts instantiation to only the named classes:

```ruby
# SAFE: explicit permitted_classes — only known-safe classes can be instantiated
data = YAML.safe_load(
  yaml_string,
  permitted_classes: [Symbol, Date, MyValueObject],
  permitted_symbols: [],
  aliases: false
)
```

4. **Avoid Marshal for any data that is not generated and consumed entirely within the same trusted process.** Marshal is appropriate for in-process caching of Ruby objects (e.g., serializing a computed result to a local cache file on the same server), but never for data that crosses any network boundary, is stored in a database accessible by multiple parties, or is visible to end users:

```ruby
# SAFE: Marshal only for trusted in-process data with integrity verification
# Sign the Marshal payload with an HMAC if it must cross a storage boundary
require 'openssl'
require 'base64'

def marshal_dump_signed(obj, key)
  payload = Base64.strict_encode64(Marshal.dump(obj))
  sig     = OpenSSL::HMAC.hexdigest('SHA256', key, payload)
  "#{sig}.#{payload}"
end

def marshal_load_verified(token, key)
  sig, payload = token.split('.', 2)
  expected = OpenSSL::HMAC.hexdigest('SHA256', key, payload)
  raise SecurityError, 'Invalid signature' unless ActiveSupport::SecurityUtils.secure_compare(expected, sig)
  Marshal.load(Base64.strict_decode64(payload))
end
```

5. **Audit all deserialization sites when upgrading Ruby or Rails.** Rails session stores, cache backends (Dalli, redis-store), and job queues (Sidekiq, Resque) may serialize Ruby objects internally. Ensure these backends are not accessible to untrusted parties, and migrate sessions to JSON-serialized formats where possible.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Rails Security Guide – Deserialization](https://guides.rubyonrails.org/security.html#deserialization)
- [Ruby docs: YAML.safe_load](https://ruby-doc.org/stdlib/libdoc/psych/rdoc/Psych.html#method-c-safe_load)
- [Ruby docs: Marshal](https://ruby-doc.org/core/Marshal.html)
- [CVE-2013-0156 – Rails YAML RCE](https://nvd.nist.gov/vuln/detail/CVE-2013-0156)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
