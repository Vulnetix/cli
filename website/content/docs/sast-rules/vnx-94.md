---
title: "VNX-94 – Code Injection"
description: "HTTP request data reaches eval, new Function, vm, string setTimeout, Python eval/exec/compile, PHP eval/assert/create_function/call_user_func, or Ruby eval/instance_eval/class_eval/module_eval, directly or through a variable."
---

## Overview

This rule reports a dynamic code evaluator whose argument carries HTTP request data: JavaScript `eval()`, `new Function()`, the `vm` module and string `setTimeout`/`setInterval`; Python `eval()`, `exec()` and `compile()`; PHP `eval()`, `assert()`, `create_function()` and a request-chosen `call_user_func()` callback; Ruby `eval()`, `instance_eval()`, `class_eval()` and `module_eval()` with a string. The request value may be used directly or through a variable assigned from it (or from such a variable) in the 25 lines above. Evaluators over constants, values passed through a numeric conversion or `ast.literal_eval`, function arguments to `setTimeout`, and Ruby block forms are not reported. Evaluation of non-constant code with no visible request source is reported by the language rules (VNX-NODE-002, VNX-PY-002), and `preg_replace` with `/e` by VNX-PHP-009. Code injection allows an attacker to supply arbitrary code that is executed by the application with the full privileges of the runtime process. This maps to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** Critical | **CWE:** [CWE-94 – Code Injection](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

Code injection is the most direct and complete form of application compromise possible: the attacker writes the code, the server runs it. Unlike SQL injection or command injection, there is no database or OS boundary — the attacker's payload executes in the same language, the same process, and with the same permissions as the application. In JavaScript, `eval(userInput)` gives the attacker access to the entire Node.js environment including `require('fs')` and `require('child_process')`. In Python, `eval(user_input)` can call `__import__('os').system('...')`. The rule also flags `setTimeout(stringArg)` and `setInterval(stringArg)` in JavaScript because these functions evaluate their first argument as code when it is a string rather than a function reference.

## What Gets Flagged

```javascript
// FLAGGED: request data evaluated directly, or through a variable
const result = eval(req.query.expr);
const body = req.body.rule;
const fn = new Function('item', body);
setTimeout("refresh('" + req.query.panel + "')", 500);
```

```python
# FLAGGED
return str(eval(request.args.get("q")))
code = request.form["code"]
exec(code, {"__builtins__": {}})
```

```php
<?php
// FLAGGED
$expr = $_GET['expr'];
eval('$result = ' . $expr . ';');
call_user_func($_GET['callback'], $data);
```

```ruby
# FLAGGED
render plain: eval(params[:expr]).to_s
Widget.class_eval(request.body.read)
```

Not flagged: `eval('1 + 2')`, `ast.literal_eval(request.args["v"])`, `setTimeout(() => refresh(req.query.panel), 500)`, `eval('$r = ' . intval($_GET['n']) . ';')`, `config.instance_eval do ... end`.

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
