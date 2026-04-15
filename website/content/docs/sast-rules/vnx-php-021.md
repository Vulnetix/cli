---
title: "VNX-PHP-021 – Laravel mass assignment via empty guarded array"
description: "Detects Laravel Eloquent models that set $guarded to an empty array or call Model::unguard(), disabling mass-assignment protection and allowing attackers to set any model attribute via request data."
---

## Overview

This rule detects two patterns that disable Laravel's mass-assignment protection: an Eloquent model that defines `protected $guarded = []`, and any call to `Model::unguard()`. Laravel's Eloquent ORM provides mass-assignment protection to prevent untrusted request data from populating sensitive model attributes. When `$guarded` is set to an empty array, every attribute on the model becomes mass-assignable, including fields like `is_admin`, `role`, `balance`, or `password` that should only be set through controlled code paths.

Mass-assignment vulnerabilities arise when applications pass entire request data arrays to model creation or update methods — a pattern encouraged by Laravel's convenience methods like `Model::create($request->all())` or `$model->fill($request->all())`. Without a `$fillable` allowlist or a non-empty `$guarded` list, these calls accept and persist any attribute present in the request, regardless of whether the user should have access to that field.

The `Model::unguard()` call globally disables mass-assignment protection for the application lifetime, affecting all models regardless of their individual configuration. This is sometimes seen in seeders or test factories but is catastrophic if left in production bootstrap code.

**Severity:** High | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

## Why This Matters

Mass-assignment privilege escalation has been used in multiple real-world attacks and was famously exploited against GitHub in 2012, where an attacker used mass-assignment to add an SSH key to any repository. In Laravel applications, the most common targets are boolean fields like `is_admin`, `email_verified`, or `active`, and role or permission identifiers.

The attack is simple: the attacker adds extra fields to a form POST or JSON request body that correspond to sensitive model attributes. If the application passes the entire request to `Model::create()` or `fill()`, those extra fields are persisted. The attacker does not need any special knowledge of the codebase — the model's attribute names often match the database column names and can be guessed from the application's behaviour or discovered via error messages.

Laravel's `$fillable` approach (explicit allowlist) is safer than `$guarded` (blacklist) because an allowlist requires developers to consciously decide what to permit, while a blacklist requires them to anticipate and list everything that must be denied — easy to get wrong as models evolve.

## What Gets Flagged

```php
// FLAGGED: $guarded = [] disables all mass-assignment protection
class User extends Model {
    protected $guarded = []; // any attribute can be set via create()/fill()
}

// FLAGGED: global unguard disables protection for all models
class AppServiceProvider extends ServiceProvider {
    public function boot() {
        Model::unguard(); // dangerous — affects every model
    }
}
```

## Remediation

1. **Replace `$guarded = []` with an explicit `$fillable` array** listing only the attributes that safe to set via user input.

2. **Remove `Model::unguard()` calls** from all production code paths, including service providers and boot methods.

3. **Use `$request->only(['field1', 'field2'])` or `$request->validated()`** to explicitly select which request fields are passed to model methods, providing a second layer of defence.

4. **Apply Laravel Form Request validation classes** to ensure only validated, expected fields reach model creation code.

```php
<?php
// SAFE: explicit $fillable allowlist — only listed attributes can be mass-assigned
class User extends Model {
    protected $fillable = [
        'name',
        'email',
        'password',
    ];
    // is_admin, role, email_verified_at are NOT fillable
}

// SAFE: controller uses request->validated() and specific fields only
class UserController extends Controller {
    public function store(CreateUserRequest $request): RedirectResponse {
        User::create($request->only(['name', 'email', 'password']));
        return redirect()->route('users.index');
    }
}
```

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CAPEC-77: Manipulating User-Controlled Variables](https://capec.mitre.org/data/definitions/77.html)
- [OWASP Mass Assignment Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Laravel Documentation – Mass Assignment](https://laravel.com/docs/eloquent#mass-assignment)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [GitHub Security Bug Bounty – Homakov mass-assignment exploit (2012)](https://github.blog/news-insights/the-library/security-audits-and-vulnerabilities/)
