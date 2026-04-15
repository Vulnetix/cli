---
title: "VNX-GQL-002 – GraphQL Query Batching or No Depth Limit (DoS)"
description: "Detects Apollo Server configured with allowBatchedHttpRequests: true, which allows attackers to send many operations in a single request and bypass rate limiting controls."
---

## Overview

This rule detects Apollo Server configured with `allowBatchedHttpRequests: true`. Query batching allows a client to send an array of multiple GraphQL operations in a single HTTP request. Without this being paired with strict per-operation rate limiting and depth controls, an attacker can send hundreds of complex operations in a single request, completely bypassing any rate limiting applied at the HTTP layer and causing denial of service through CPU exhaustion. This maps to CWE-770 (Allocation of Resources Without Limits or Throttling).

**Severity:** Medium | **CWE:** [CWE-770 – Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Why This Matters

GraphQL's flexible query structure creates unique denial-of-service opportunities that HTTP-layer rate limiting cannot fully address. With batching enabled, an attacker can pack 50 deeply-nested queries into a single HTTP request — your load balancer sees one request, but your server executes 50 expensive resolver chains. Combined with the lack of depth limits, a maliciously nested query like `{ user { friends { friends { friends { friends { posts { comments { ... } } } } } } } }` can cause exponential resolver execution, locking up your event loop or exhausting your database connection pool.

Real-world GraphQL DoS attacks have taken production services down within seconds because the default GraphQL execution engine has no built-in query complexity limits.

## What Gets Flagged

```javascript
// FLAGGED: batching enabled without compensating controls
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: true,
});
```

## Remediation

1. **Disable batching unless you have a specific, well-understood use case for it.** Most applications do not need HTTP-level query batching:

   ```javascript
   // SAFE: batching disabled (default)
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     // allowBatchedHttpRequests omitted — defaults to false
   });
   ```

2. **Add query depth and complexity limits using graphql-depth-limit and graphql-cost-analysis:**

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
       costAnalysis({ maximumCost: 1000, defaultCost: 1 })
     ],
   });
   ```

3. **Apply rate limiting per-operation, not just per-request.** If you must support batching (e.g., for a trusted internal client), count each operation in a batch toward the rate limit separately.

4. **Set query timeout limits** to bound the maximum execution time for any single query regardless of complexity:

   ```javascript
   // Apollo Server plugin to enforce per-request timeouts
   const timeoutPlugin = {
     async requestDidStart() {
       return {
         async executionDidStart() {
           return {
             willResolveField({ info }) {
               // implement per-field timeout tracking
             }
           };
         }
       };
     }
   };
   ```

## References

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [OWASP GraphQL Cheat Sheet – Query Depth Limiting](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [graphql-depth-limit package](https://www.npmjs.com/package/graphql-depth-limit)
- [graphql-cost-analysis package](https://www.npmjs.com/package/graphql-cost-analysis)
- [Apollo Server – Batching Requests](https://www.apollographql.com/docs/apollo-server/requests/#batching)
- [CAPEC-469: HTTP DoS](https://capec.mitre.org/data/definitions/469.html)
