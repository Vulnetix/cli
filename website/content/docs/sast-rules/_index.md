---
title: SAST Rules
weight: 5
---

Vulnetix ships built-in SAST rules written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) and evaluated by the Open Policy Agent engine. Rules are organised by language and security category. Each rule page explains what the rule detects, why it matters, and how to remediate the finding.

## Rule Categories

{{< cards >}}
  {{< card link="#android" title="Android" subtitle="7 rules — manifest, WebView, exported components, storage, API keys, crypto" >}}
  {{< card link="#bash" title="Bash / Shell" subtitle="7 rules — eval injection, curl-pipe, pipefail, unquoted vars, hardcoded secrets" >}}
  {{< card link="#c" title="C / C++" subtitle="6 rules — buffer overflow, format string, command injection, use-after-free" >}}
  {{< card link="#csharp" title="C# / .NET" subtitle="10 rules — SQL injection, command injection, deserialization, XXE, SSRF, CSRF" >}}
  {{< card link="#crypto" title="Cryptography" subtitle="10 rules — weak ciphers, broken hashes, TLS, key size, timing attacks, IV reuse" >}}
  {{< card link="#docker" title="Docker" subtitle="8 rules — least-privilege, supply chain, HEALTHCHECK, version pinning" >}}
  {{< card link="#go" title="Go" subtitle="16 rules — injection, SSRF, path traversal, deserialization, concurrency bugs" >}}
  {{< card link="#graphql" title="GraphQL" subtitle="4 rules — introspection, DoS, query injection, field suggestion disclosure" >}}
  {{< card link="#java" title="Java" subtitle="27 rules — injection, deserialization, CSRF, XPath, JPQL, crypto, file upload" >}}
  {{< card link="#jwt" title="JWT" subtitle="6 rules — signature bypass, missing expiry, hardcoded secret, none algorithm" >}}
  {{< card link="#kotlin" title="Kotlin" subtitle="5 rules — ECB cipher, weak RSA, insecure cookie, cleartext socket, weak hash" >}}
  {{< card link="#llm" title="LLM / AI" subtitle="7 rules — prompt injection, RCE, hardcoded API key, SQL via LLM output" >}}
  {{< card link="#nodejs" title="Node.js" subtitle="26 rules — injection, XSS, deserialization, crypto, YAML, JWT, shell injection" >}}
  {{< card link="#php" title="PHP" subtitle="26 rules — SQL, XSS, XXE, session fixation, file upload, LDAP, mass assignment" >}}
  {{< card link="#python" title="Python" subtitle="21 rules — deserialization, SSTI, SSL, PRNG, paramiko, tarfile slip, ML models" >}}
  {{< card link="#ruby" title="Ruby" subtitle="10 rules — deserialization, SQL injection, XSS, mass assignment, TLS, send injection" >}}
  {{< card link="#rust" title="Rust" subtitle="6 rules — lockfile, panic, unsafe, command injection, Result misuse, integer cast" >}}
  {{< card link="#secrets" title="Secrets / Credentials" subtitle="32 rules — AWS, Azure, GCP, tokens, API keys, PGP, OAuth" >}}
  {{< card link="#swift" title="Swift / iOS" subtitle="6 rules — hardcoded keys, NSLog, UserDefaults, TLS disabled, WebView, PRNG" >}}
  {{< card link="#terraform" title="Terraform / IaC" subtitle="8 rules — S3 public, security groups, IAM wildcard, unencrypted storage, IMDSv1" >}}
{{< /cards >}}

## Android {#android}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-ANDROID-001](vnx-android-001) | Android insecure manifest configuration | High |
| [VNX-ANDROID-002](vnx-android-002) | Android WebView JavaScript enabled | High |
| [VNX-ANDROID-003](vnx-android-003) | Android exported component without permission check | High |
| [VNX-ANDROID-004](vnx-android-004) | Android SharedPreferences used for sensitive data storage | High |
| [VNX-ANDROID-005](vnx-android-005) | Android network security config allows plaintext HTTP traffic | High |
| [VNX-ANDROID-006](vnx-android-006) | Android hardcoded API key in strings.xml | High |
| [VNX-ANDROID-007](vnx-android-007) | Android weak cryptography using AES in ECB mode | High |

## Bash / Shell {#bash}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-BASH-001](vnx-bash-001) | eval with potentially user-controlled input | Critical |
| [VNX-BASH-002](vnx-bash-002) | curl or wget output piped directly to shell interpreter | High |
| [VNX-BASH-003](vnx-bash-003) | Missing set -euo pipefail in Bash script | Medium |
| [VNX-BASH-004](vnx-bash-004) | Unquoted variable used in command or test | Medium |
| [VNX-BASH-005](vnx-bash-005) | Hardcoded secret or password in shell script | High |
| [VNX-BASH-006](vnx-bash-006) | Global IFS reassignment in shell script | Medium |
| [VNX-BASH-007](vnx-bash-007) | Unquoted command substitution in shell script | Medium |

## C / C++ {#c}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-C-001](vnx-c-001) | Use of unbounded string copy function (strcpy/strcat/gets) | High |
| [VNX-C-002](vnx-c-002) | Format string injection via non-literal format argument | High |
| [VNX-C-003](vnx-c-003) | OS command injection via system() or popen() | High |
| [VNX-C-004](vnx-c-004) | Use-after-free: pointer used after free() | High |
| [VNX-C-005](vnx-c-005) | Integer overflow in malloc/calloc size arithmetic | High |
| [VNX-C-006](vnx-c-006) | Use of alloca() for dynamic stack allocation | Medium |

## C# / .NET {#csharp}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-CS-001](vnx-cs-001) | C# SQL injection via string concatenation in SqlCommand | High |
| [VNX-CS-002](vnx-cs-002) | C# command injection via Process.Start with user input | High |
| [VNX-CS-003](vnx-cs-003) | C# XXE via XmlDocument with XmlResolver enabled | High |
| [VNX-CS-004](vnx-cs-004) | C# insecure deserialization via BinaryFormatter or SoapFormatter | Critical |
| [VNX-CS-005](vnx-cs-005) | C# missing ValidateAntiForgeryToken on state-changing actions | High |
| [VNX-CS-006](vnx-cs-006) | C# insecure random number generator (System.Random for security) | Medium |
| [VNX-CS-007](vnx-cs-007) | C# path traversal via Path.Combine with user input | High |
| [VNX-CS-008](vnx-cs-008) | C# SSRF via WebClient or HttpClient with user-supplied URL | High |
| [VNX-CS-009](vnx-cs-009) | C# use of weak cryptographic algorithm (MD5, SHA1, DES, 3DES) | High |
| [VNX-CS-010](vnx-cs-010) | C# hardcoded connection string with credentials | High |

## Cryptography {#crypto}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-CRYPTO-001](vnx-crypto-001) | MD5 usage detected | Medium |
| [VNX-CRYPTO-002](vnx-crypto-002) | SHA-1 usage detected | Medium |
| [VNX-CRYPTO-003](vnx-crypto-003) | AES in ECB mode | High |
| [VNX-CRYPTO-004](vnx-crypto-004) | Broken or obsolete cipher | High |
| [VNX-CRYPTO-005](vnx-crypto-005) | TLS certificate validation disabled | High |
| [VNX-CRYPTO-006](vnx-crypto-006) | Weak RSA key size | High |
| [VNX-CRYPTO-007](vnx-crypto-007) | Weak password hashing / insufficient KDF iterations | High |
| [VNX-CRYPTO-008](vnx-crypto-008) | Timing attack via direct comparison of secrets | High |
| [VNX-CRYPTO-009](vnx-crypto-009) | Use of cryptographically weak PRNG (rand/srand in C/C++) | High |
| [VNX-CRYPTO-010](vnx-crypto-010) | Hardcoded IV, nonce, or salt in cryptographic operation | High |

## Docker {#docker}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-DOCKER-001](vnx-docker-001) | Dockerfile missing USER directive | Medium |
| [VNX-DOCKER-002](vnx-docker-002) | Dockerfile FROM :latest tag | Medium |
| [VNX-DOCKER-003](vnx-docker-003) | Secret in Dockerfile ARG or ENV | High |
| [VNX-DOCKER-004](vnx-docker-004) | Dockerfile ADD with remote URL | Medium |
| [VNX-DOCKER-005](vnx-docker-005) | Dockerfile privileged container flag | High |
| [VNX-DOCKER-006](vnx-docker-006) | Dockerfile uses ADD instead of COPY for local files | Low |
| [VNX-DOCKER-007](vnx-docker-007) | Dockerfile missing HEALTHCHECK instruction | Low |
| [VNX-DOCKER-008](vnx-docker-008) | Dockerfile package manager install without version pinning | Medium |

## Go {#go}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-GO-001](vnx-go-001) | Missing go.sum | High |
| [VNX-GO-002](vnx-go-002) | Command injection via exec.Command | High |
| [VNX-GO-003](vnx-go-003) | SQL injection via fmt.Sprintf | Critical |
| [VNX-GO-004](vnx-go-004) | TLS InsecureSkipVerify enabled | High |
| [VNX-GO-005](vnx-go-005) | Go open redirect | Medium |
| [VNX-GO-006](vnx-go-006) | Go server-side request forgery | High |
| [VNX-GO-007](vnx-go-007) | Go path traversal | High |
| [VNX-GO-008](vnx-go-008) | Go weak PRNG for security | Medium |
| [VNX-GO-009](vnx-go-009) | Go text/template used for HTML | High |
| [VNX-GO-010](vnx-go-010) | Go weak cipher usage | High |
| [VNX-GO-011](vnx-go-011) | Go gob deserialization from HTTP request | Medium |
| [VNX-GO-012](vnx-go-012) | Go HTTP response header injection (CRLF) | Medium |
| [VNX-GO-013](vnx-go-013) | Go zip/tar slip via archive entry name | High |
| [VNX-GO-014](vnx-go-014) | Go sync.Mutex Lock() without deferred Unlock() | Medium |
| [VNX-GO-015](vnx-go-015) | Go sync.WaitGroup.Add() called inside goroutine | Medium |
| [VNX-GO-016](vnx-go-016) | Go integer downcast after strconv.Atoi/ParseInt | Medium |

## GraphQL {#graphql}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-GQL-001](vnx-gql-001) | GraphQL introspection enabled in production | Medium |
| [VNX-GQL-002](vnx-gql-002) | GraphQL query depth/batching enables DoS | Medium |
| [VNX-GQL-003](vnx-gql-003) | GraphQL query string injection via string concatenation | High |
| [VNX-GQL-004](vnx-gql-004) | GraphQL field suggestion disclosure enabled | Low |

## Java {#java}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-JAVA-001](vnx-java-001) | Command injection via Runtime.exec() | High |
| [VNX-JAVA-002](vnx-java-002) | Spring actuator endpoints exposed | Medium |
| [VNX-JAVA-003](vnx-java-003) | SQL injection via string concatenation | Critical |
| [VNX-JAVA-004](vnx-java-004) | XML external entity (XXE) injection | High |
| [VNX-JAVA-005](vnx-java-005) | Insecure deserialization | Critical |
| [VNX-JAVA-006](vnx-java-006) | Insecure TLS trust manager | Critical |
| [VNX-JAVA-007](vnx-java-007) | Java open redirect | Medium |
| [VNX-JAVA-008](vnx-java-008) | Java server-side request forgery | High |
| [VNX-JAVA-009](vnx-java-009) | Java path traversal | High |
| [VNX-JAVA-010](vnx-java-010) | Spring CSRF protection disabled | Medium |
| [VNX-JAVA-011](vnx-java-011) | Java expression language injection | Critical |
| [VNX-JAVA-012](vnx-java-012) | Java LDAP injection | High |
| [VNX-JAVA-013](vnx-java-013) | Java XPath injection | High |
| [VNX-JAVA-014](vnx-java-014) | Java zip slip via ZipEntry getName() | High |
| [VNX-JAVA-015](vnx-java-015) | Java JPQL/HQL injection via string concatenation | High |
| [VNX-JAVA-016](vnx-java-016) | Java weak PRNG (java.util.Random) for security | High |
| [VNX-JAVA-017](vnx-java-017) | Java HTTP response splitting (CRLF) | High |
| [VNX-JAVA-018](vnx-java-018) | Java RSA cipher without OAEP padding | High |
| [VNX-JAVA-019](vnx-java-019) | Java hardcoded cryptographic key literal | Critical |
| [VNX-JAVA-020](vnx-java-020) | Java static IV reuse in block cipher | High |
| [VNX-JAVA-021](vnx-java-021) | Java sensitive data logged (password, token, secret) | Medium |
| [VNX-JAVA-022](vnx-java-022) | Java insecure temporary file creation | Medium |
| [VNX-JAVA-023](vnx-java-023) | Java unrestricted file upload | High |
| [VNX-JAVA-024](vnx-java-024) | Java XML entity expansion (Billion Laughs) | High |
| [VNX-JAVA-025](vnx-java-025) | Java hardcoded password or credential | Critical |
| [VNX-JAVA-026](vnx-java-026) | Java Spring file serving without access control | High |
| [VNX-JAVA-027](vnx-java-027) | Java Spring security headers disabled | Medium |

## JWT {#jwt}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-JWT-001](vnx-jwt-001) | JWT signature verification disabled | Critical |
| [VNX-JWT-002](vnx-jwt-002) | JWT token signed without expiration | Medium |
| [VNX-JWT-003](vnx-jwt-003) | JWT signing with hardcoded secret | High |
| [VNX-JWT-004](vnx-jwt-004) | JWT algorithm explicitly set to 'none' | Critical |
| [VNX-JWT-005](vnx-jwt-005) | Sensitive credential data stored in JWT payload | High |
| [VNX-JWT-006](vnx-jwt-006) | JWT missing audience or issuer verification | Medium |

## Kotlin {#kotlin}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-KOTLIN-001](vnx-kotlin-001) | Kotlin ECB cipher mode — deterministic, unauthenticated encryption | High |
| [VNX-KOTLIN-002](vnx-kotlin-002) | Kotlin RSA key smaller than 2048 bits | High |
| [VNX-KOTLIN-003](vnx-kotlin-003) | Kotlin cookie missing HttpOnly flag | Medium |
| [VNX-KOTLIN-004](vnx-kotlin-004) | Kotlin unencrypted plain socket (cleartext transmission) | High |
| [VNX-KOTLIN-005](vnx-kotlin-005) | Kotlin MD5 or SHA-1 used as cryptographic hash | Medium |

## LLM / AI {#llm}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-LLM-001](vnx-llm-001) | LLM prompt injection via user-controlled input | High |
| [VNX-LLM-002](vnx-llm-002) | LLM output passed to code execution (RCE) | Critical |
| [VNX-LLM-003](vnx-llm-003) | Hardcoded LLM API key | Critical |
| [VNX-LLM-004](vnx-llm-004) | User input directly in LLM system prompt | High |
| [VNX-LLM-005](vnx-llm-005) | LangChain arbitrary code execution tool enabled | Critical |
| [VNX-LLM-006](vnx-llm-006) | LLM output interpolated into SQL query | Critical |
| [VNX-LLM-007](vnx-llm-007) | torch.load() without weights_only=True | High |

## Node.js {#nodejs}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-NODE-001](vnx-node-001) | Missing npm lock file | High |
| [VNX-NODE-002](vnx-node-002) | eval() or new Function() in JavaScript | High |
| [VNX-NODE-003](vnx-node-003) | Command injection via child_process | High |
| [VNX-NODE-004](vnx-node-004) | Express app without helmet | Medium |
| [VNX-NODE-005](vnx-node-005) | innerHTML or dangerouslySetInnerHTML usage | Medium |
| [VNX-NODE-006](vnx-node-006) | Prototype pollution via merge | High |
| [VNX-NODE-007](vnx-node-007) | Node.js SQL injection | Critical |
| [VNX-NODE-008](vnx-node-008) | Node.js open redirect | Medium |
| [VNX-NODE-009](vnx-node-009) | Node.js server-side request forgery | High |
| [VNX-NODE-010](vnx-node-010) | Node.js path traversal | High |
| [VNX-NODE-011](vnx-node-011) | Node.js server-side template injection | Critical |
| [VNX-NODE-012](vnx-node-012) | Client-side XSS via innerHTML or v-html | High |
| [VNX-NODE-013](vnx-node-013) | Node.js command injection via child_process | Critical |
| [VNX-NODE-014](vnx-node-014) | NoSQL injection in MongoDB | High |
| [VNX-NODE-015](vnx-node-015) | WebSocket server without origin verification (CSWSH) | Medium |
| [VNX-NODE-016](vnx-node-016) | ReDoS via user-controlled regular expression | Medium |
| [VNX-NODE-017](vnx-node-017) | Insecure deserialization via node-serialize | Critical |
| [VNX-NODE-018](vnx-node-018) | JWT decoded without signature verification | High |
| [VNX-NODE-019](vnx-node-019) | Hardcoded JWT or session secret | High |
| [VNX-NODE-020](vnx-node-020) | Deprecated crypto.createCipher/createDecipher without IV | High |
| [VNX-NODE-021](vnx-node-021) | XXE via libxmljs with noent:true | High |
| [VNX-NODE-022](vnx-node-022) | Shell injection via shelljs exec() | Critical |
| [VNX-NODE-023](vnx-node-023) | Unsafe YAML.load() with untrusted input | High |
| [VNX-NODE-024](vnx-node-024) | postMessage without origin validation | Medium |
| [VNX-NODE-025](vnx-node-025) | Insecure express-session or cookie-session configuration | Medium |
| [VNX-NODE-026](vnx-node-026) | Child process spawn with shell:true | High |

## PHP {#php}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-PHP-001](vnx-php-001) | Missing composer.lock | High |
| [VNX-PHP-002](vnx-php-002) | Dangerous function in PHP | High |
| [VNX-PHP-003](vnx-php-003) | PHP file inclusion with variable path | Critical |
| [VNX-PHP-004](vnx-php-004) | PHP open redirect | Medium |
| [VNX-PHP-005](vnx-php-005) | PHP server-side request forgery | High |
| [VNX-PHP-006](vnx-php-006) | PHP object injection via unserialize | Critical |
| [VNX-PHP-007](vnx-php-007) | PHP extract on superglobal | High |
| [VNX-PHP-008](vnx-php-008) | PHP phpinfo exposure | Medium |
| [VNX-PHP-009](vnx-php-009) | PHP preg_replace with /e modifier | Critical |
| [VNX-PHP-010](vnx-php-010) | PHP type juggling in comparison | High |
| [VNX-PHP-011](vnx-php-011) | PHP SQL injection via string concatenation | Critical |
| [VNX-PHP-012](vnx-php-012) | PHP reflected XSS via echo/print of user input | High |
| [VNX-PHP-013](vnx-php-013) | PHP XXE via LIBXML_NOENT or LIBXML_DTDLOAD | High |
| [VNX-PHP-014](vnx-php-014) | PHP session fixation via user-controlled session ID | High |
| [VNX-PHP-015](vnx-php-015) | PHP unrestricted file upload via move_uploaded_file | High |
| [VNX-PHP-016](vnx-php-016) | PHP weak hash function (md5/sha1) | Medium |
| [VNX-PHP-017](vnx-php-017) | PHP LDAP injection via user-controlled filter | High |
| [VNX-PHP-018](vnx-php-018) | PHP sensitive debug output disclosure | Medium |
| [VNX-PHP-019](vnx-php-019) | PHP insecure cipher mode (AES-CBC) | Medium |
| [VNX-PHP-020](vnx-php-020) | PHP curl SSL certificate verification disabled | High |
| [VNX-PHP-021](vnx-php-021) | Laravel mass assignment via empty guarded array | High |
| [VNX-PHP-022](vnx-php-022) | PHP open redirect via non-literal redirect destination | Medium |
| [VNX-PHP-023](vnx-php-023) | PHP anonymous LDAP bind without password | High |
| [VNX-PHP-024](vnx-php-024) | PHP mb_ereg_replace with eval modifier | Critical |
| [VNX-PHP-025](vnx-php-025) | PHP deprecated mcrypt encryption functions | High |
| [VNX-PHP-026](vnx-php-026) | PHP session poisoning via user-controlled session key | High |

## Python {#python}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-PY-001](vnx-py-001) | Missing Python lock file | High |
| [VNX-PY-002](vnx-py-002) | eval()/exec() usage in Python | High |
| [VNX-PY-003](vnx-py-003) | Insecure deserialization with pickle | High |
| [VNX-PY-004](vnx-py-004) | yaml.load() without SafeLoader | High |
| [VNX-PY-005](vnx-py-005) | Weak PRNG for security operations | Medium |
| [VNX-PY-006](vnx-py-006) | Django DEBUG=True | Medium |
| [VNX-PY-007](vnx-py-007) | subprocess with shell=True | High |
| [VNX-PY-008](vnx-py-008) | Flask debug mode enabled | High |
| [VNX-PY-009](vnx-py-009) | Jinja2 autoescape disabled | High |
| [VNX-PY-010](vnx-py-010) | SSL verification disabled in requests | High |
| [VNX-PY-011](vnx-py-011) | Python SQL injection | Critical |
| [VNX-PY-012](vnx-py-012) | Python server-side template injection | Critical |
| [VNX-PY-013](vnx-py-013) | Python ML/AI insecure deserialization | Critical |
| [VNX-PY-014](vnx-py-014) | Python XML external entity injection | High |
| [VNX-PY-015](vnx-py-015) | Python ReDoS via user-controlled regular expression | Medium |
| [VNX-PY-016](vnx-py-016) | Django mass assignment via request data unpacking | High |
| [VNX-PY-017](vnx-py-017) | MD5 or SHA1 used as password hash | High |
| [VNX-PY-018](vnx-py-018) | Insecure temporary file creation via tempfile.mktemp() | Medium |
| [VNX-PY-019](vnx-py-019) | Paramiko implicit host key trust | High |
| [VNX-PY-020](vnx-py-020) | tarfile.extractall() without path validation (zip slip) | High |
| [VNX-PY-021](vnx-py-021) | Weak or deprecated SSL/TLS protocol version | High |

## Ruby {#ruby}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-RUBY-001](vnx-ruby-001) | Missing Gemfile.lock | High |
| [VNX-RUBY-002](vnx-ruby-002) | eval() or system() in Ruby | High |
| [VNX-RUBY-003](vnx-ruby-003) | Insecure deserialization in Ruby | Critical |
| [VNX-RUBY-004](vnx-ruby-004) | Ruby SQL injection | Critical |
| [VNX-RUBY-005](vnx-ruby-005) | Ruby XSS via html_safe or raw | High |
| [VNX-RUBY-006](vnx-ruby-006) | Ruby mass assignment | High |
| [VNX-RUBY-007](vnx-ruby-007) | YAML.load() insecure deserialization | Critical |
| [VNX-RUBY-008](vnx-ruby-008) | Open3.pipeline with dynamic command | High |
| [VNX-RUBY-009](vnx-ruby-009) | Ruby dynamic method dispatch via send with user input | High |
| [VNX-RUBY-010](vnx-ruby-010) | OpenSSL certificate verification disabled (VERIFY_NONE) | High |

## Rust {#rust}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-RUST-001](vnx-rust-001) | Missing Cargo.lock | High |
| [VNX-RUST-002](vnx-rust-002) | Rust unwrap may panic | Low |
| [VNX-RUST-003](vnx-rust-003) | Rust unsafe block | Medium |
| [VNX-RUST-004](vnx-rust-004) | Rust command injection via process::Command with format! | High |
| [VNX-RUST-005](vnx-rust-005) | panic!() or unwrap()/expect() in function returning Result | Medium |
| [VNX-RUST-006](vnx-rust-006) | Integer truncation or sign-change cast after parsing | Medium |

## Secrets / Credentials {#secrets}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-SEC-001](vnx-sec-001) | AWS access key ID | Critical |
| [VNX-SEC-002](vnx-sec-002) | Private key committed | Critical |
| [VNX-SEC-003](vnx-sec-003) | AWS secret access key | Critical |
| [VNX-SEC-004](vnx-sec-004) | GitHub or GitLab token | Critical |
| [VNX-SEC-005](vnx-sec-005) | GCP API key | Critical |
| [VNX-SEC-006](vnx-sec-006) | Stripe secret key | Critical |
| [VNX-SEC-007](vnx-sec-007) | Slack token or webhook | High |
| [VNX-SEC-008](vnx-sec-008) | Database connection string with credentials | Critical |
| [VNX-SEC-009](vnx-sec-009) | SendGrid API key | High |
| [VNX-SEC-010](vnx-sec-010) | Package registry token | Critical |
| [VNX-SEC-011](vnx-sec-011) | Hardcoded JWT token | High |
| [VNX-SEC-012](vnx-sec-012) | CORS wildcard or origin reflection | High |
| [VNX-SEC-013](vnx-sec-013) | Insecure cookie configuration | Medium |
| [VNX-SEC-014](vnx-sec-014) | Hardcoded password in variable | High |
| [VNX-SEC-015](vnx-sec-015) | JWT algorithm none attack | Critical |
| [VNX-SEC-016](vnx-sec-016) | TLS verification disabled in shell command | Medium |
| [VNX-SEC-017](vnx-sec-017) | Plaintext protocol URL | Medium |
| [VNX-SEC-018](vnx-sec-018) | AI provider API key | Critical |
| [VNX-SEC-019](vnx-sec-019) | GCP service account key | Critical |
| [VNX-SEC-020](vnx-sec-020) | GitLab access token | Critical |
| [VNX-SEC-021](vnx-sec-021) | Twilio API credentials | Critical |
| [VNX-SEC-022](vnx-sec-022) | Sensitive data in log statement | Medium |
| [VNX-SEC-023](vnx-sec-023) | GitHub Actions expression injection via event data | High |
| [VNX-SEC-024](vnx-sec-024) | OAuth token stored in localStorage | Medium |
| [VNX-SEC-025](vnx-sec-025) | Azure Storage Account key hardcoded | Critical |
| [VNX-SEC-026](vnx-sec-026) | DigitalOcean personal access token hardcoded | Critical |
| [VNX-SEC-027](vnx-sec-027) | Hugging Face API token hardcoded | High |
| [VNX-SEC-028](vnx-sec-028) | npm access token hardcoded | High |
| [VNX-SEC-029](vnx-sec-029) | PyPI upload token hardcoded | High |
| [VNX-SEC-030](vnx-sec-030) | Google OAuth client secret hardcoded | High |
| [VNX-SEC-031](vnx-sec-031) | Mailgun API key hardcoded | High |
| [VNX-SEC-032](vnx-sec-032) | PGP private key block hardcoded | Critical |

## Swift / iOS {#swift}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-SWIFT-001](vnx-swift-001) | Swift hardcoded API key or secret in source | High |
| [VNX-SWIFT-002](vnx-swift-002) | Swift NSLog with potentially sensitive data | Medium |
| [VNX-SWIFT-003](vnx-swift-003) | Swift insecure data storage via UserDefaults for sensitive values | High |
| [VNX-SWIFT-004](vnx-swift-004) | Swift TLS certificate validation disabled | High |
| [VNX-SWIFT-005](vnx-swift-005) | Swift WKWebView JavaScript auto-open-windows enabled | Medium |
| [VNX-SWIFT-006](vnx-swift-006) | Swift insecure random number generator (arc4random/rand) | Medium |

## Terraform / IaC {#terraform}

| Rule ID | Name | Severity |
|---------|------|----------|
| [VNX-TF-001](vnx-tf-001) | Terraform AWS S3 bucket with public ACL | High |
| [VNX-TF-002](vnx-tf-002) | Terraform AWS security group with unrestricted ingress (0.0.0.0/0) | High |
| [VNX-TF-003](vnx-tf-003) | Terraform AWS RDS instance publicly accessible | High |
| [VNX-TF-004](vnx-tf-004) | Terraform IAM policy with wildcard Action (*) | High |
| [VNX-TF-005](vnx-tf-005) | Terraform AWS EBS volume unencrypted | Medium |
| [VNX-TF-006](vnx-tf-006) | Terraform AWS EC2 IMDSv1 enabled (SSRF risk) | Medium |
| [VNX-TF-007](vnx-tf-007) | Terraform AWS EKS cluster public API endpoint | Medium |
| [VNX-TF-008](vnx-tf-008) | Terraform AWS provider with hardcoded static credentials | Critical |
