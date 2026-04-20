---
title: "VNX-94 – Code Injection"
description: "Detect dynamic code evaluation functions (eval, exec, new Function, etc.) called with user-controlled or dynamic input, enabling arbitrary code execution."
---

## Overview

This rule flags calls to dynamic code evaluation functions — `eval()`, `exec()`, `new Function()`, `compile()`, PHP's `eval()`, and Ruby's `eval()`/`instance_eval()` — especially when user-controlled data or dynamically constructed strings are passed as the argument. Code injection allows an attacker to supply arbitrary code that is executed by the application with the full privileges of the runtime process. This maps to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** Critical | **CWE:** [CWE-94 – Code Injection](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

Code injection is the most direct and complete form of application compromise possible: the attacker writes the code, the server runs it. Unlike SQL injection or command injection, there is no database or OS boundary — the attacker's payload executes in the same language, the same process, and with the same permissions as the application. In JavaScript, `eval(userInput)` gives the attacker access to the entire Node.js environment including `require('fs')` and `require('child_process')`. In Python, `eval(user_input)` can call `__import__('os').system('...')`. The rule also flags `setTimeout(stringArg)` and `setInterval(stringArg)` in JavaScript because these functions evaluate their first argument as code when it is a string rather than a function reference.

## What Gets Flagged

```javascript
// FLAGGED: eval with user input
app.post('/calculate', (req, res) => {
    const expr = req.body.expression;
    const result = eval(expr);  // attacker sends: process.mainModule.require('child_process').exec('...')
    res.json({ result });
});
```

```javascript
// FLAGGED: new Function with dynamic content
const fn = new Function('return ' + req.query.formula);
```

```javascript
// FLAGGED: setTimeout with string argument
setTimeout("cleanup('" + userId + "')", 1000);
```

```python
# FLAGGED: Python eval with input
@app.route('/calc')
def calc():
    expr = request.args['expr']
    result = eval(expr)   # allows __import__('os').system('id')
    return str(result)
```

```python
# FLAGGED: Python exec — flagged regardless
exec(compile(user_code, '<string>', 'exec'))
```

```php
<?php
// FLAGGED: PHP eval
$code = $_POST['code'];
eval($code);  // direct code injection
```

```php
<?php
// FLAGGED: preg_replace with /e modifier
preg_replace('/' . $_GET['pattern'] . '/e', $_GET['replace'], $subject);
```

```ruby
# FLAGGED: Ruby eval
eval(params[:code])
```

## Remediation

1. **Do not use eval or equivalent functions with external data.** In almost all cases there is a safer alternative.

```python
# SAFE: Use ast.literal_eval for parsing data expressions (not code)
import ast

def parse_value(s: str):
    # Only parses Python literals: strings, numbers, lists, dicts, tuples, bools, None
    return ast.literal_eval(s)

# SAFE: For mathematical expressions, use a dedicated expression parser
# e.g. simpleeval, numexpr, or operator trees — never eval()
```

```javascript
// SAFE: Use Function properly — only with static, developer-controlled template strings
// Better: use a math expression library like mathjs
const { evaluate } = require('mathjs');
app.post('/calculate', (req, res) => {
    try {
        const result = evaluate(req.body.expression);  // sandboxed math evaluation
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});
```

```javascript
// SAFE: setTimeout with a function reference, not a string
setTimeout(() => cleanup(userId), 1000);
```

```php
<?php
// SAFE: Use a whitelist-based expression evaluator rather than eval
// Or restructure logic to avoid dynamic code execution entirely
// If dynamic dispatch is needed, use a dispatch table:
$allowed = ['add' => fn($a,$b) => $a + $b, 'mul' => fn($a,$b) => $a * $b];
$op = $_POST['operation'];
if (!array_key_exists($op, $allowed)) {
    http_response_code(400); exit;
}
$result = $allowed[$op]($a, $b);
```

2. **Replace `preg_replace` with `/e` modifier** with `preg_replace_callback()`. The `/e` modifier was deprecated in PHP 5.5 and removed in PHP 7.0.

3. **Use a sandboxed execution environment** if dynamic code execution is a genuine requirement. Node.js has `vm.runInNewContext()`, Python has `RestrictedPython`, and there are purpose-built sandboxes for all major languages.

4. **Audit all existing uses of eval/exec** even when the argument appears to be developer-controlled — code paths change over time and a future refactor may introduce a vulnerability.

## References

- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [Python ast.literal_eval documentation](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
