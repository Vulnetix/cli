---
title: "VNX-GQL-004 – GraphQL Field Suggestion Disclosure Enabled"
description: "Reports JavaScript/TypeScript GraphQL servers (Apollo Server, graphql-yoga, NestJS GraphQLModule, express-graphql, Mercurius) in a project that nowhere suppresses graphql-js 'Did you mean' field suggestions."
---

## Overview

This rule reports each GraphQL server constructed in JavaScript or TypeScript (`new ApolloServer(...)`, `createYoga(...)`, `GraphQLModule.forRoot(...)`, `graphqlHTTP(...)`, `app.register(mercurius, ...)`) when no file in the project suppresses field suggestions. These servers run graphql-js validation, which answers a malformed query with errors such as `Cannot query field "usernam" on type "Query". Did you mean "username"?`. Those hints leak field names even when introspection is disabled. This maps to CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

A project counts as mitigated when any of its files sets `hideSchemaDetailsFromClientErrors: true` (Apollo Server), uses GraphQL Armor (`ApolloArmor`, `EnvelopArmor`, `blockFieldSuggestions`), installs a disable-suggestions plugin, or rewrites "Did you mean" messages in a `formatError`/`maskError` hook. Error masking alone (`maskedErrors` in graphql-yoga) does not hide validation errors, so it is not counted. Test files, comments and string literals are not reported; servers in other languages are not covered.

**Severity:** Low | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Schema information is a reconnaissance asset for attackers. Many GraphQL deployments disable introspection in production to prevent automated schema dumping, but field suggestions bypass that control entirely: an attacker can enumerate the schema field by field by submitting slightly misspelled field names and reading the suggestions in the error responses. This technique is documented in GraphQL security research and is implemented in tools such as `clairvoyance`.

CAPEC-118 (Collect and Analyze Information) and MITRE ATT&CK T1592 (Gather Victim Host Information) apply when an attacker uses the suggestion mechanism to map internal schema structure. Even if the leaked fields are not directly exploitable, knowing their names reduces the attacker's effort in crafting injection or authorisation bypass attempts.

Disabling suggestions does not reduce functionality for legitimate users — it only affects what error messages reveal when a query contains a typo. Authenticated developer tooling should connect to non-production environments where suggestions can remain enabled.

## What Gets Flagged

```javascript
// FLAGGED: Apollo Server with default (suggesting) validation errors
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});

// FLAGGED: graphql-yoga; maskedErrors does not hide validation suggestions
export const yoga = createYoga({ schema, maskedErrors: true });
```

Not flagged, when anywhere in the project:

```javascript
const armor = new ApolloArmor({ blockFieldSuggestion: { enabled: true } });
export const server = new ApolloServer({ typeDefs, resolvers, ...armor.protect() });
```

## Remediation

1. **Apollo Server**: set `hideSchemaDetailsFromClientErrors: true` so validation errors no longer carry "Did you mean" hints.

   ```javascript
   // SAFE
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     hideSchemaDetailsFromClientErrors: true,
   });
   ```

2. **graphql-yoga, Envelop, Mercurius or older Apollo versions**: use GraphQL Armor's field-suggestion blocker.

   ```javascript
   // SAFE
   import { blockFieldSuggestions } from '@escape.tech/graphql-armor-block-field-suggestions';

   const yoga = createYoga({ schema, plugins: [blockFieldSuggestions()] });
   ```

3. **Combine with disabled introspection** (VNX-GQL-001). Each control alone leaves the schema discoverable through the other.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-118: Collect and Analyze Information](https://capec.mitre.org/data/definitions/118.html)
- [MITRE ATT&CK T1592 – Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)
- [Apollo Server – Production considerations](https://www.apollographql.com/docs/apollo-server/security/production-considerations/)
- [GraphQL Armor – Block field suggestions](https://escape.tech/graphql-armor/docs/plugins/block-field-suggestions/)
- [graphql-yoga – Error masking](https://the-guild.dev/graphql/yoga-server/docs/features/error-masking)
- [OWASP GraphQL Cheat Sheet – Disable introspection and suggestions](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [clairvoyance – GraphQL schema enumeration via suggestions](https://github.com/nikitastupin/clairvoyance)
