---
title: "VNX-GQL-004 – GraphQL Field Suggestion Disclosure Enabled"
description: "Detects Apollo Server and graphql-yoga configurations that do not explicitly disable field suggestions, leaking internal schema field names through error messages in production."
---

## Overview

This rule detects GraphQL server configurations in Apollo Server and graphql-yoga (or similar servers) that do not explicitly disable field suggestion (also called schema suggestion or did-you-mean). When field suggestions are enabled, GraphQL returns error messages such as `Cannot query field "usernam" on type "Query". Did you mean "username"?` in response to malformed queries. This leaks field names that exist in the schema but are not discoverable through standard introspection — for example, fields hidden by introspection-disabling middleware. This maps to CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

For Apollo Server, the configuration option to disable this is `suggestions: false`. For graphql-yoga and similar servers, the equivalent is `maskedErrors: true`, which replaces all error details with a generic message. Both options should be enabled in production deployments, where error details are security-sensitive rather than developer-helpful.

**Severity:** Low | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Schema information is a reconnaissance asset for attackers. Many GraphQL deployments disable introspection in production to prevent automated schema dumping, but field suggestions bypass that control entirely: an attacker can enumerate the schema field by field by submitting slightly misspelled field names and reading the suggestions in the error responses. This technique is documented in GraphQL security research and is implemented in tools such as `clairvoyance`.

CAPEC-118 (Collect and Analyze Information) and MITRE ATT&CK T1592 (Gather Victim Host Information) apply when an attacker uses the suggestion mechanism to map internal schema structure. Even if the leaked fields are not directly exploitable, knowing their names reduces the attacker's effort in crafting injection or authorisation bypass attempts.

Disabling suggestions does not reduce functionality for legitimate users — it only affects what error messages reveal when a query contains a typo. Authenticated developer tooling should connect to non-production environments where suggestions can remain enabled.

## What Gets Flagged

```javascript
// FLAGGED: ApolloServer created without suggestions: false
const server = new ApolloServer({
  typeDefs,
  resolvers,
});

// FLAGGED: graphql-yoga created without maskedErrors: true
const yoga = createYoga({
  schema,
});
```

## Remediation

1. **Set `suggestions: false` in Apollo Server** to prevent field name hints from appearing in production error responses.

   ```javascript
   // SAFE: suggestions disabled in production
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     // Disable field suggestions in production to prevent schema enumeration
     ...(process.env.NODE_ENV === "production" && { suggestions: false }),
   });
   ```

2. **Set `maskedErrors: true` in graphql-yoga** to replace detailed error messages with a generic response in production.

   ```javascript
   // SAFE: masked errors prevent schema leakage in production
   const yoga = createYoga({
     schema,
     maskedErrors: process.env.NODE_ENV === "production",
   });
   ```

3. **Combine suggestion disabling with introspection disabling** for defence in depth. Both controls together prevent automated schema discovery through both the introspection API and the suggestion mechanism.

   ```javascript
   // SAFE: both introspection and suggestions disabled in production
   const isProd = process.env.NODE_ENV === "production";
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     introspection: !isProd,
     suggestions: !isProd,
   });
   ```

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-118: Collect and Analyze Information](https://capec.mitre.org/data/definitions/118.html)
- [MITRE ATT&CK T1592 – Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)
- [Apollo Server – Security configuration (suggestions)](https://www.apollographql.com/docs/apollo-server/security/security/)
- [graphql-yoga – Error masking](https://the-guild.dev/graphql/yoga-server/docs/features/error-masking)
- [OWASP GraphQL Cheat Sheet – Disable introspection and suggestions](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [clairvoyance – GraphQL schema enumeration via suggestions](https://github.com/nikitastupin/clairvoyance)
