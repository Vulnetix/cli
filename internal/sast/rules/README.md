# Vulnetix SAST Rules

This directory contains Rego-based SAST (Static Application Security Testing) rules for the Vulnetix CLI tool.
Each rule is designed to detect specific security vulnerabilities in source code.

## Rule Structure

Each rule file follows the naming convention: `vnx-{language}-{number}.rego`

Example: `vnx-go-001.rego` is a Go language rule.

## Rule Metadata

Each rule includes a metadata block with the following fields:
- `id`: Unique rule identifier (e.g., "VNX-GO-001")
- `name`: Human-readable rule name
- `description`: Detailed explanation of the vulnerability
- `help_uri`: Link to documentation for this rule
- `languages`: List of languages this rule applies to
- `severity`: Criticality level (low, medium, high, critical)
- `level`: Alert level (info, warning, error)
- `kind`: Type of rule (sast, secrets, etc.)
- `cwe`: Common Weakness Enumeration IDs
- `capec`: Common Attack Pattern Enumeration and Classification IDs
- `attack_technique`: MITRE ATT&CK technique IDs
- `cvssv4`: CVSS v4 score (if applicable)
- `cwss`: Common Weakness Scoring System string (if applicable)
- `tags`: Keywords for categorization

## Supported Languages

Rules are available for the following languages:
- Go (go)
- Node.js/JavaScript (node)
- Python (py)
- Java (java)
- C#/.NET (cs)
- PHP (php)
- Ruby (ruby)
- Rust (rust)
- Swift (swift)
- Android/Kotlin (android)
- Bash (bash)
- C/C++ (c)
- Cryptography (crypto)
- Dockerfile (docker)
- GraphQL (gql)
- JSON Web Tokens (jwt)
- Low/No Code/LLM (llm)
- Security (sec)
- Terraform/HCL (tf)
- HTML (html)

## Rule Categories

Rules cover various security categories including:
- Authentication and Session Management
- Authorization
- Cryptography
- Data Protection
- Input Validation and Sanitization
- Logging and Error Handling
- Secure Communication
- Web Frontend Security
- WebRTC Security
- And more based on OWASP ASVS

## Rule Sources

Many rules are derived from the OWASP Application Security Verification Standard (ASVS) 5.0, specifically from the following sections:
- V1: Encoding and Sanitization
- V2: Validation and Business Logic
- V3: Web Frontend Security
- V4: API and Web Service
- V5: File Handling
- V6: Authentication
- V7: Session Management
- V8: Authorization
- V9: Self-contained Tokens
- V10: OAuth and OIDC
- V11: Cryptography
- V12: Secure Communication
- V13: Configuration
- V14: Data Protection
- V15: Secure Coding and Architecture
- V16: Security Logging and Error Handling
- V17: WebRTC

## Usage

These rules are used by the Vulnetix CLI tool during SAST scanning to identify potential security vulnerabilities in source code.