---
title: "VNX-93 – CRLF Injection into mail or protocol headers"
description: "HTTP request data placed into a CRLF-delimited mail header or protocol line (SMTP commands, raw headers, PHP mail() headers, email.mime headers) without removing CR/LF."
---

## Overview

VNX-93 maps to [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html). It reports three shapes, in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby:

- a line that builds text from a `\r\n` literal with request data placed before that terminator, or from a header-name literal (`"From: "`, `"To: "`, `"Subject: "`, `"Reply-To: "`, `"MAIL FROM:"`, `"RCPT TO:"`...) with request data anywhere on the line;
- PHP `mail()`/`mb_send_mail()` whose to, subject, headers or additional-parameters argument (not the body) carries request data;
- Python `email.mime` message headers (`msg["Subject"] = ...`, `add_header`, `replace_header`) assigned request data.

Request data can be used inline, interpolated, or through a variable assigned from it in the 25 lines above. Not reported: values passed through CR/LF replacement, `filter_var`/`FILTER_VALIDATE_EMAIL` or an encoding call, values validated before use, request data only in a mail body, Python `EmailMessage` (its default policy rejects CR/LF in headers), and lines that write a response body or a log. HTTP response headers are covered by VNX-GO-012, VNX-JAVA-017 and VNX-644.

**Severity:** Medium | **CWE:** [CWE-93](https://cwe.mitre.org/data/definitions/93.html) | **Languages:** go, java, node, php, python, ruby

## Why This Matters

Mail headers and line protocols such as SMTP end each header or command with CRLF. A request value containing `%0d%0a` ends the line early, so the attacker adds `Bcc:` recipients to a contact form (turning it into a spam relay), changes the sender, or issues further SMTP commands.

## What Gets Flagged

```php
<?php
$email = $_POST['email'];
$headers = "From: " . $email . "\r\n";                          // FLAGGED
mail("support@example.com", $_POST['subject'], $_POST['message'], $headers);  // FLAGGED (subject)
```

```python
msg = MIMEText(request.form["body"])
msg["Subject"] = request.form["subject"]                        # FLAGGED
```

```go
from := r.FormValue("from")
msg := []byte("From: " + from + "\r\n" +                         // FLAGGED
	"To: support@example.com\r\n")
```

```javascript
socket.write('MAIL FROM:<' + req.body.from + '>\r\n');          // FLAGGED
```

Not flagged: `$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);`, `str_replace(array("\r", "\n"), '', $_POST['subject'])`, `EmailMessage()` headers, `[]byte("\r\n" + body)` (body after the headers), `res.write('Name: ' + req.query.name + '\r\n')`.

## Remediation

1. Validate addresses as addresses (`filter_var(..., FILTER_VALIDATE_EMAIL)`, `mail.ParseAddress`, `InternetAddress`) before they reach a header.
2. Strip `\r` and `\n` from any other request value used in a header or protocol line.
3. Prefer a mail library that encodes headers and rejects CR/LF (Python `EmailMessage`, JavaMail, nodemailer) over building messages by hand.

## References

- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
