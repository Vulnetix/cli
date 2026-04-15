---
title: "VNX-GQL-003 – GraphQL Query String Injection via String Concatenation"
description: "Detects GraphQL operation documents built by concatenating or interpolating user-controlled input into the query string, allowing attackers to inject arbitrary fields, aliases, or directives."
---

## Overview

This rule detects GraphQL operation strings that are built by concatenating or interpolating user-controlled values directly into the query, mutation, or subscription document string. In JavaScript and TypeScript this appears as template literals with `${req.body.*}` or `${params.*}` embedded inside an operation; in Python as f-strings with user-controlled expressions inside the GraphQL operation text; and in any language as string concatenation using `+` to build a query from request variables.

GraphQL, like SQL, has a strict query language syntax. When user input is embedded directly into an operation string rather than passed as a bound variable, the attacker controls the **structure** of the operation — not just its data values. The safe pattern is to use **static operation documents** with a separate variables map: the operation text is a compile-time constant, and all user-supplied values are passed as typed, named variables that the GraphQL runtime handles as data rather than syntax.

**Severity:** High | **CWE:** [CWE-89 – Improper Neutralization of Special Elements Used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) | **CAPEC:** [CAPEC-66 – SQL Injection](https://capec.mitre.org/data/definitions/66.html)

**OWASP ASVS v4:** V5.3.4 — Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from injection attacks.

## Why This Matters

GraphQL query injection is the GraphQL analogue of SQL injection. An attacker who can inject into an operation string can:

- **Pivot to resolvers that expose sensitive data** by appending field selections that were not part of the intended operation
- **Enumerate the schema beyond what introspection reveals** by probing field names through crafted injections
- **Bypass field-level authorisation checks** that only apply to statically defined operations
- **Add aliases** to circumvent field-level rate limits that key on field names
- **Inject directives** (`@skip`, `@include`) to alter control flow in unexpected ways

**Concrete attack scenario:** A search feature builds a GraphQL query by interpolating the user's search term:

```javascript
// Vulnerable server-side code
const query = `query { search(term: "${req.body.term}") { title } }`;
```

An attacker submits the following as `term`:

```
") { adminUsers { email passwordHash } search(term: "x
```

This closes the `search` field selection and opens an additional `adminUsers` field. If the `adminUsers` resolver lacks its own independent authorisation check, the attacker receives the full administrator list in the response.

The OWASP Web Security Testing Guide and OWASP GraphQL Cheat Sheet both explicitly identify server-side query construction from user input as a high-severity injection vector.

## What Gets Flagged

```javascript
// FLAGGED: template literal with request body interpolated into operation
const query = `query { user(id: "${req.body.userId}") { name email } }`;

// FLAGGED: string concatenation building operation from request param
const op = "mutation { createPost(title: '" + req.body.title + "') { id } }";
```

```python
# FLAGGED: Python f-string building operation from user input
query = f'query {{ user(name: "{request.args.get("name")}") {{ id }} }}'
```

## Remediation

### Use Static Operation Documents with a Variables Map

The operation string is a compile-time constant. All user-controlled values are passed through the `variables` argument as typed GraphQL variables. The GraphQL runtime ensures variables are treated as data values and can never alter the operation structure — they are constrained to the declared type and cannot contain GraphQL syntax.

**JavaScript / TypeScript (Apollo Client / urql / graphql-request):**

```javascript
// SAFE: static operation document with typed variables
const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) {
      name
      email
    }
  }
`;

// Pass user input only through the variables map — never into the operation string
const result = await client.query({
  query: GET_USER,
  variables: { id: req.body.userId },
});
```

**Server-side (Node.js with graphql-http or Apollo Server):**

```javascript
// SAFE: static operation stored as a constant — never built from request data
const SEARCH_QUERY = `
  query Search($term: String!) {
    search(term: $term) {
      title
    }
  }
`;

const result = await graphql({
  schema,
  source: SEARCH_QUERY,
  variableValues: { term: req.body.term },  // user input goes here, not in source
});
```

### Store Operations as `.graphql` Files

Treat operation documents as source code artefacts checked into version control. Any dynamic construction of operation strings is a code smell that should require justification in code review:

```graphql
# SAFE: operations/getUser.graphql — no dynamic construction possible
query GetUser($id: ID!) {
  user(id: $id) {
    name
    email
  }
}
```

### Python (gql / sgqlc)

Use the `variables` argument provided by GraphQL client libraries rather than f-strings or `%`-formatting:

```python
# SAFE: gql client with variables dict
from gql import gql, Client

GET_USER = gql("""
  query GetUser($name: String!) {
    user(name: $name) { id email }
  }
""")

# user input goes in variable_values dict — never into the query string
result = client.execute(GET_USER, variable_values={"name": request.args.get("name")})
```

### Graphene (Django) — Resolvers Receive Typed Arguments

In Graphene-Django, resolver arguments are already typed by the schema. Do not pass unvalidated strings to raw database queries within resolvers — use ORM queries, not string interpolation:

```python
# SAFE: resolver uses typed argument, passes it to ORM — no raw query building
class Query(graphene.ObjectType):
    user = graphene.Field(UserType, name=graphene.String(required=True))

    def resolve_user(self, info, name):
        # ORM handles parameterisation — never concatenate name into a raw SQL string
        return User.objects.filter(name=name).first()
```

## References

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [OWASP WSTG – Testing GraphQL](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)
- [Escape Tech – SQL Injection in GraphQL](https://escape.tech/blog/sql-injection-in-graphql/)
- [Praetorian – Identifying SQL Injections in a GraphQL API](https://www.praetorian.com/blog/identifying-sql-injections-in-a-graphql-api/)
- [GraphQL Specification – Variables](https://spec.graphql.org/October2021/#sec-Language.Variables)
- [Apollo Client – Operation Best Practices](https://www.apollographql.com/docs/react/data/operation-best-practices/)
- [CWE-89: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
