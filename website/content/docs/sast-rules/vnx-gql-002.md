---
title: "VNX-GQL-002 – GraphQL Query Batching or No Depth Limit (DoS)"
description: "Detects Apollo Server configured with allowBatchedHttpRequests: true, which allows attackers to send many operations in a single request and bypass rate limiting controls."
---

## Overview

This rule detects Apollo Server configured with `allowBatchedHttpRequests: true`. Query batching allows a client to send an array of multiple GraphQL operations in a single HTTP request. Without this being paired with strict per-operation rate limiting and query depth/complexity controls, an attacker can send hundreds of complex operations in a single request, completely bypassing any HTTP-layer rate limiting and causing denial of service through CPU or database connection exhaustion.

GraphQL's flexible query language creates DoS attack surfaces that HTTP-layer controls cannot address alone. Both HTTP-level batching and deeply nested single queries can exhaust server resources — this rule targets the former; depth/complexity limits address the latter.

**Severity:** Medium | **CWE:** [CWE-770 – Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) | **CAPEC:** [CAPEC-469 – HTTP DoS](https://capec.mitre.org/data/definitions/469.html)

**OWASP ASVS v4:** V13.4.1 — Verify that a query allowlist or a combination of depth limiting and amount limiting is used to prevent GraphQL DoS as a result of expensive, nested queries.

## Why This Matters

GraphQL's flexible query structure creates unique denial-of-service opportunities that HTTP-layer rate limiting cannot fully address:

**Batching amplification:** With `allowBatchedHttpRequests: true`, an attacker sends a JSON array of 50 operations in a single HTTP request. Your load balancer counts one request; your server executes 50 expensive resolver chains. Standard rate limiting (requests per minute per IP) is bypassed entirely.

**Nested query exhaustion:** A maliciously nested query can cause exponential resolver execution even without batching:

```graphql
# This single query can lock up your event loop or exhaust your DB connection pool
{
  user {
    friends {
      friends {
        friends {
          friends {
            posts {
              comments {
                author {
                  friends { id }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Real-world GraphQL DoS attacks have taken production services offline within seconds because the default GraphQL execution engine has no built-in query complexity limits. The OWASP GraphQL Cheat Sheet explicitly calls out both batching and depth limiting as required controls.

## What Gets Flagged

```javascript
// FLAGGED: batching enabled without compensating controls
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: true,  // <-- flagged
});
```

## Remediation

### Disable Batching (Recommended Default)

Most applications do not need HTTP-level query batching. The default in Apollo Server is `false`:

```javascript
// SAFE: batching disabled (default behaviour)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // allowBatchedHttpRequests omitted — defaults to false
});
```

### Add Query Depth and Complexity Limits (Apollo Server / graphql-js)

Install `graphql-depth-limit` and a complexity analysis library, then apply them as validation rules:

```javascript
// Install: npm install graphql-depth-limit graphql-cost-analysis
import depthLimit from 'graphql-depth-limit';
import costAnalysis from 'graphql-cost-analysis';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false,
  validationRules: [
    depthLimit(7),
    costAnalysis({ maximumCost: 1000, defaultCost: 1 }),
  ],
});
```

### Graphene (Python)

Use the built-in `depth_limit_validator` from `graphene.validation`:

```python
from graphene_django.views import GraphQLView
from graphene.validation import depth_limit_validator

class DepthLimitedGraphQLView(GraphQLView):
    def get_validation_rules(self):
        return [depth_limit_validator(max_depth=10)]

# In urls.py
urlpatterns = [
    path('graphql/', DepthLimitedGraphQLView.as_view(graphiql=False)),
]
```

### graphql-java

Use `MaxQueryDepthInstrumentation` and `MaxQueryComplexityInstrumentation`:

```java
GraphQL graphQL = GraphQL.newGraphQL(schema)
    .instrumentation(new ChainedInstrumentation(Arrays.asList(
        new MaxQueryDepthInstrumentation(10),
        new MaxQueryComplexityInstrumentation(200)
    )))
    .build();
```

graphql-java ships with a default maximum depth of 20. Set this explicitly to a value appropriate for your schema rather than relying on the default.

### gqlgen (Go)

```go
// In graph/schema.resolvers.go — add complexity limits via handler config
import "github.com/99designs/gqlgen/graphql/handler/extension"

srv := handler.NewDefaultServer(generated.NewExecutableSchema(cfg))
srv.Use(extension.FixedComplexityLimit(300))
```

### If You Must Enable Batching

If batching is required for a trusted internal client (e.g., a BFF layer), apply all of the following compensating controls:

- Count each operation in a batch separately against rate limits
- Set a maximum number of operations per batch (e.g., no more than 10)
- Apply query depth and complexity limits to every operation in the batch
- Restrict batching to authenticated sessions only

```javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: true,
  validationRules: [depthLimit(7), costAnalysis({ maximumCost: 500 })],
  plugins: [
    {
      async requestDidStart({ request }) {
        // Reject batches larger than 10 operations
        if (Array.isArray(request.body) && request.body.length > 10) {
          throw new Error('Batch size limit exceeded');
        }
      },
    },
  ],
});
```

## References

- [OWASP GraphQL Cheat Sheet – Query Depth Limiting](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [HowToGraphQL – Security](https://www.howtographql.com/advanced/4-security/)
- [Escape Tech – Cyclic Queries and Depth Limiting](https://escape.tech/blog/cyclic-queries-and-depth-limit/)
- [graphql-java – Limits Documentation](https://www.graphql-java.com/documentation/limits/)
- [Graphene-Python – Query Validation](https://docs.graphene-python.org/en/latest/execution/queryvalidation/)
- [gqlgen – Complexity Reference](https://gqlgen.com/reference/complexity/)
- [Apollo Server – Batching Requests](https://www.apollographql.com/docs/apollo-server/requests/#batching)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CAPEC-469: HTTP DoS](https://capec.mitre.org/data/definitions/469.html)
- [MITRE ATT&CK T1499 – Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [graphql-depth-limit package](https://www.npmjs.com/package/graphql-depth-limit)
- [graphql-cost-analysis package](https://www.npmjs.com/package/graphql-cost-analysis)
