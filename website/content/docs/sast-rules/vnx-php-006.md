---
title: "VNX-PHP-006 – PHP Object Injection via unserialize()"
description: "Detect unserialize() and maybe_unserialize() on a request value (superglobals, php://input, request accessors, also wrapped in base64_decode() and similar) without an allowed_classes restriction."
---

## Overview

This rule flags calls to `unserialize()` and `maybe_unserialize()` (a WordPress helper) where the input comes from user-controlled superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`), inline or through a variable assigned from one, unless `allowed_classes` restricts object creation. PHP's serialization format can encode arbitrary object graphs; when `unserialize()` processes attacker-supplied data, it instantiates PHP objects and calls their `__wakeup()` and `__destruct()` magic methods during the deserialization process — before any application logic has a chance to validate the result. This maps to [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html).

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

PHP Object Injection (POI) is a code execution primitive that does not require a file write or a file inclusion vulnerability. An attacker constructs a serialized string that, when deserialized, instantiates objects from classes already loaded in the application. By chaining together classes whose `__wakeup()`, `__destruct()`, `__toString()`, or other magic methods perform dangerous operations — writing files, executing commands, making HTTP requests — the attacker assembles a "gadget chain" that executes arbitrary code when the string is deserialized.

Ready-made gadget chains exist for virtually every major PHP framework and CMS. Tools like `phpggc` (PHP Generic Gadget Chains) automate the generation of exploit payloads targeting Symfony, Laravel, WordPress, Zend/Laminas, Yii, Magento, and Drupal. If your application uses any of these frameworks and calls `unserialize()` on untrusted data, it is almost certainly exploitable without any further preconditions.

## What Gets Flagged

A call whose deserialised value is a request value, inline (optionally wrapped in a decoding function) or through a variable assigned from one a few lines above, with no `allowed_classes` option that disables or restricts object creation.

```php
// FLAGGED
$cart = unserialize($_COOKIE["cart"]);
$prefs = unserialize(base64_decode($_COOKIE["prefs"]));

$payload = $_POST["data"];
$obj = unserialize($payload);

$settings = maybe_unserialize( stripslashes( $_POST["settings"] ) );
```

Not flagged: `unserialize($x, ["allowed_classes" => false])` or an explicit class list; a value authenticated with `hash_equals()` first; a request value used only as a lookup key (`unserialize($redis->get("session:" . $_COOKIE["sid"]))`); cache, queue and file payloads the application wrote itself; methods named `unserialize`; `json_decode()`.

## Remediation

1. **Replace `unserialize()` with `json_decode()` for data exchange formats.** JSON cannot represent PHP objects or trigger magic methods — it decodes to arrays and scalars only. This eliminates the object injection surface entirely:

```php
// SAFE: JSON decoding — no object instantiation, no magic methods
$prefs = json_decode($_COOKIE['preferences'], true);
if (!is_array($prefs)) {
    $prefs = [];
}
```

2. **If you must use `unserialize()`, set `allowed_classes` to `false` or an explicit whitelist.** Since PHP 7.0, `unserialize()` accepts an `options` array. Setting `allowed_classes` to `false` prevents any class from being instantiated during deserialization, neutralizing gadget chain attacks:

```php
// SAFE: allowed_classes restricts which objects can be created
$data = unserialize($input, ['allowed_classes' => false]);

// SAFE: or allow only specific, known-safe classes
$data = unserialize($input, ['allowed_classes' => ['MyValueObject', 'UserPreferences']]);
```

3. **Sign or authenticate serialized data before trusting it.** If you serialize data and store it in a cookie, session, or database field that could be tampered with, include an HMAC signature computed with a server-side secret. Verify the signature before deserializing:

```php
// SAFE: HMAC-authenticated serialization (sign before store, verify before load)
function serialize_signed(mixed $data, string $key): string {
    $payload = base64_encode(serialize($data));
    $sig     = hash_hmac('sha256', $payload, $key);
    return $sig . '.' . $payload;
}

function unserialize_verified(string $token, string $key): mixed {
    [$sig, $payload] = explode('.', $token, 2) + ['', ''];
    $expected = hash_hmac('sha256', $payload, $key);
    if (!hash_equals($expected, $sig)) {
        throw new \RuntimeException('Invalid signature');
    }
    return unserialize(base64_decode($payload), ['allowed_classes' => false]);
}
```

4. **Audit every `unserialize()` call in the codebase**, including indirect uses through ORM hydrators, cache libraries, and session handlers. Many PHP session handlers serialize and deserialize session data automatically — ensure the session storage backend is not accessible to untrusted parties.

5. **Keep framework versions current.** Framework maintainers regularly remove unsafe magic methods from classes to neutralize known gadget chains. An up-to-date Composer `composer.lock` combined with `allowed_classes` restrictions is the strongest combination.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: unserialize() – allowed_classes](https://www.php.net/manual/en/function.unserialize.php)
- [phpggc – PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
