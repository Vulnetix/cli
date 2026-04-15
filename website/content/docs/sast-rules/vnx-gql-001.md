---
title: "VNX-GQL-001 – GraphQL Introspection Enabled in Production"
description: "Detects Apollo Server configured with introspection: true or express-graphql with graphiql: true, exposing the full API schema to unauthenticated attackers."
---

## Overview

This rule detects GraphQL servers where introspection is explicitly enabled (`introspection: true`) or the GraphiQL IDE is left active (`graphiql: true`). GraphQL introspection is a built-in feature that lets any client query the server for a complete description of its schema — every type, query, mutation, field name, and argument. While useful during development, leaving introspection enabled in production provides a detailed reconnaissance map to attackers.

**Introspection is enabled by default in most GraphQL frameworks**, including Apollo Server (prior to v3), express-graphql, graphene-django, and graphql-java. You must explicitly disable it in production deployments.

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) | **CAPEC:** [CAPEC-116 – Excavation](https://capec.mitre.org/data/definitions/116.html)

**OWASP ASVS v4:** V13.4.1 — Verify that a query allowlist or a combination of depth limiting and amount limiting is in place for GraphQL APIs, and that introspection is disabled in production environments.

## Why This Matters

Attackers routinely send introspection queries as an early reconnaissance step against any GraphQL endpoint they discover. With the full schema, an attacker immediately knows:

- Every field name your data model uses — potentially revealing internal naming like `internalAdminFlag`, `deletedAt`, or `stripeCustomerId`
- Every mutation available, including dangerous admin operations
- Argument types and structures that help craft injection payloads
- Deprecated fields that may lack the same hardening as current fields

Tools like [graphql-voyager](https://github.com/graphql-kit/graphql-voyager) and [InQL](https://github.com/doyensec/inql) are specifically designed to visualise and attack GraphQL APIs using introspection results. Even after disabling introspection, note that **field suggestion** (covered separately in VNX-GQL-004) can still allow schema enumeration — both controls should be applied together.

## What Gets Flagged

```javascript
// FLAGGED: introspection: true in Apollo Server config
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,   // <-- flagged
});
```

```javascript
// FLAGGED: GraphiQL enabled in express-graphql
app.use('/graphql', graphqlHTTP({
  schema: schema,
  graphiql: true,        // <-- flagged
}));
```

## Remediation

### Apollo Server

Apollo Server v3+ automatically disables introspection when `NODE_ENV` is `production`. In all versions, disable it explicitly using an environment check:

```javascript
// SAFE: introspection only in non-production environments
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
```

### express-graphql

```javascript
// SAFE: GraphiQL only in development
app.use('/graphql', graphqlHTTP({
  schema: schema,
  graphiql: process.env.NODE_ENV === 'development',
}));
```

### Graphene (Python / Django)

Disable via Django settings, or use a middleware that intercepts `__schema` queries:

```python
# settings.py
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'SCHEMA_INTROSPECTION_ENABLED': False,
}
```

Or with a custom middleware for non-Django setups:

```python
from graphql import GraphQLError

class DisableIntrospectionMiddleware:
    def resolve(self, next, root, info, **kwargs):
        if info.field_name.startswith('__'):
            raise GraphQLError("Introspection is disabled in production.")
        return next(root, info, **kwargs)
```

### graphql-java

Use the built-in `NoIntrospectionGraphqlFieldVisibility` to strip introspection from the schema entirely:

```java
GraphQLSchema schema = GraphQLSchema.newSchema()
    .query(queryType)
    .fieldVisibility(NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY)
    .build();
```

### Defence in Depth: Pair with Depth Limiting

Disabling introspection does not prevent abuse of queries attackers have already discovered. Add depth limiting as a complementary control:

```javascript
// Install: npm install graphql-depth-limit
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  validationRules: [depthLimit(7)],
});
```

If you need introspection for internal tooling, require authentication for introspection queries rather than enabling it globally. Some GraphQL security plugins (such as [GraphQL Armor](https://github.com/Escape-Technologies/graphql-armor)) support role-based introspection access.

## References

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Apollo Server – Production Considerations: Introspection](https://www.apollographql.com/docs/apollo-server/security/production-considerations/#introspection)
- [Apollo Blog – Why You Should Disable GraphQL Introspection in Production](https://www.apollographql.com/blog/why-you-should-disable-graphql-introspection-in-production)
- [Graphene-Python – Query Validation](https://docs.graphene-python.org/en/latest/execution/queryvalidation/)
- [graphql-java – Limits Documentation](https://www.graphql-java.com/documentation/limits/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-116: Excavation](https://capec.mitre.org/data/definitions/116.html)
- [MITRE ATT&CK T1590 – Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
- [graphql-depth-limit package](https://www.npmjs.com/package/graphql-depth-limit)
- [GraphQL Armor – open-source security plugin](https://github.com/Escape-Technologies/graphql-armor)
