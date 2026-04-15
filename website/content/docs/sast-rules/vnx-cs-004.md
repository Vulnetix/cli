---
title: "VNX-CS-004 – C# Insecure Deserialization via BinaryFormatter or SoapFormatter"
description: "Detects use of BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter, and JavaScriptSerializer, which deserialise arbitrary .NET object graphs and can execute attacker-controlled code."
---

## Overview

This rule detects instantiation or use of .NET serialisation formatters that deserialise arbitrary type graphs: `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, and `JavaScriptSerializer`. These formatters can reconstruct any .NET type present in the loaded assemblies — including types with constructors or property setters that execute code — purely from a byte stream or string provided as input.

The core danger is that deserialisation with these types is effectively a code-execution primitive when given attacker-controlled input. An attacker does not need to find a custom gadget; the .NET runtime class library contains well-documented gadget chains (such as those involving `ObjectDataProvider`, `WindowsIdentity`, or `TypeConfuseDelegate`) that can chain together to call arbitrary methods, including `Process.Start` or `Assembly.Load`. These chains are publicly documented and reliably exploitable across many .NET Framework and .NET Core versions.

Microsoft has marked `BinaryFormatter` obsolete (SYSLIB0011) in .NET 5+ and disabled it by default in .NET 7+. Applications still using these types are carrying a high-severity known-unsafe dependency.

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Insecure deserialization has been in the OWASP Top 10 since 2017 and has produced some of the most severe vulnerabilities in widely used .NET software. CVE-2019-1391 (Microsoft SharePoint), CVE-2020-0688 (Microsoft Exchange), and dozens of Jenkins, Jira, and WebLogic CVEs all exploited unsafe deserialisation to achieve Remote Code Execution without authentication. The attack surface is particularly dangerous in middleware: any application that deserialises objects from HTTP request bodies, cookies, view state, distributed caches, or message queues is potentially reachable by an attacker who has no other foothold on the system.

`LosFormatter` and `ObjectStateFormatter` are especially significant because they underpin ASP.NET Web Forms view state. Historically, view state was MAC-protected but not encrypted, and obtaining the machine key (via a path traversal or file read vulnerability) allowed an attacker to forge malicious view state payloads that executed code when the page was processed.

`JavaScriptSerializer` with a custom `JavaScriptTypeResolver` can reconstruct arbitrary types from JSON, similar to `BinaryFormatter`. Even without a type resolver, using these serialisers for untrusted input is considered unsafe in modern .NET security guidance.

## What Gets Flagged

```csharp
// FLAGGED: BinaryFormatter instantiation
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);

// FLAGGED: SoapFormatter.Deserialize called
var sf = new SoapFormatter();
object result = sf.Deserialize(Request.InputStream);

// FLAGGED: NetDataContractSerializer
var serializer = new NetDataContractSerializer();
var data = serializer.Deserialize(inputStream);
```

## Remediation

1. Replace `BinaryFormatter` with `System.Text.Json.JsonSerializer` for new code. For existing serialised data that must be migrated, build a one-time migration path that reads the old format once and re-persists using the new serialiser.
2. Replace `SoapFormatter` with `DataContractSerializer` (for existing SOAP contracts) or `XmlSerializer` with strict schema validation.
3. For `JavaScriptSerializer`, migrate to `System.Text.Json` or `Newtonsoft.Json` without a type resolver.
4. Never deserialise data from untrusted sources with any of the flagged types, even if the data is signed or encrypted — signing and encryption protect integrity and confidentiality but do not prevent gadget-chain exploitation if the signature key is ever compromised.
5. If you must keep `BinaryFormatter` temporarily for compatibility, add the `AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true)` switch only behind a feature flag, document the risk, and track removal as a priority remediation item.

```csharp
// SAFE: System.Text.Json — does not execute arbitrary .NET type constructors
string json = JsonSerializer.Serialize(myObject);
MyType result = JsonSerializer.Deserialize<MyType>(json);

// SAFE: XmlSerializer — serialises only declared members of known types
var xmlSerializer = new XmlSerializer(typeof(MyType));
using var reader = new StringReader(xmlInput);
var result = (MyType)xmlSerializer.Deserialize(reader);
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Microsoft Docs: BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [ysoserial.net – .NET deserialization payload generator (research)](https://github.com/pwntester/ysoserial.net)
