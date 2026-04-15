---
title: "VNX-GQL-001 – GraphQL Introspection Enabled in Production"
description: "Detects Apollo Server configured with introspection: true or express-graphql with graphiql: true, exposing the full API schema to unauthenticated attackers."
---

## Overview

This rule detects GraphQL servers where introspection is explicitly enabled (`introspection: true`) or the GraphiQL IDE is left active (`graphiql: true`). GraphQL introspection is a built-in feature that lets any client query the server for a complete description of its schema — every type, query, mutation, field name, and argument. While useful during development, leaving introspection enabled in production provides a detailed reconnaissance map to attackers. This maps to CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Attackers routinely send introspection queries as an early reconnaissance step against any GraphQL endpoint they discover. With the full schema, an attacker immediately knows every field name your data model uses (potentially revealing internal naming like `internalAdminFlag`, `deletedAt`, or `stripeCustomerId`), every mutation available (including dangerous admin operations), argument types and structures that help craft injection payloads, and deprecated fields that may lack the same hardening as current fields.

Tools like `graphql-voyager` and `InQL` are specifically designed to visualise and attack GraphQL APIs based on introspection results. Disabling introspection in production does not prevent a determined attacker from enumerating your API through brute-forcing, but it significantly raises the cost and removes the free reconnaissance layer.

## What Gets Flagged

```javascript
// FLAGGED: introspection: true in Apollo Server config
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});
```

```javascript
// FLAGGED: GraphiQL enabled in express-graphql
app.use('/graphql', graphqlHTTP({
  schema: schema,
  graphiql: true,
}));
```

## Remediation

1. **Disable introspection in production using environment detection:**

   ```javascript
   // SAFE: introspection only in non-production environments
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     introspection: process.env.NODE_ENV !== 'production',
   });
   ```

2. **Disable GraphiQL in production:**

   ```javascript
   // SAFE: GraphiQL only in development
   app.use('/graphql', graphqlHTTP({
     schema: schema,
     graphiql: process.env.NODE_ENV === 'development',
   }));
   ```

3. **Add query depth limiting** to protect against deeply nested query attacks, even without introspection:

   ```javascript
   // Install: npm install graphql-depth-limit
   import depthLimit from 'graphql-depth-limit';

   const server = new ApolloServer({
     typeDefs,
     resolvers,
     introspection: false,
     validationRules: [depthLimit(7)],
   });
   ```

4. **If you need introspection for internal tooling**, require authentication for introspection queries rather than disabling it entirely. Some GraphQL security plugins support role-based introspection access.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Apollo Server – Introspection Configuration](https://www.apollographql.com/docs/apollo-server/security/production-considerations/#introspection)
- [graphql-depth-limit package](https://www.npmjs.com/package/graphql-depth-limit)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
