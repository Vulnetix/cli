---
title: "VNX-GO-038 – Potential mass assignment via struct binding"
description: "Detects Go handlers that bind a request body into a value and then save that same value whole (GORM Create/Save/Updates, Mongo InsertOne, repository Insert/Update), allowing mass assignment."
---

## Overview

This rule flags Go HTTP handlers that bind the request body into a value (`json.NewDecoder(r.Body).Decode`, `json.Unmarshal` of the body, gin `ShouldBind*`/`Bind*`, echo `c.Bind`, fiber `c.BodyParser`) and then pass that same value whole to a create or update call (GORM `Create`/`Save`/`Updates`, Mongo `InsertOne`/`UpdateOne`, a repository `Insert`/`Update`). Mass assignment (also called auto-binding or over-posting) lets an attacker supply values for fields such as `IsAdmin`, `Role`, `Balance` or `Verified` that the application never intended to accept. Binding into a dedicated input type whose fields are copied, or restricting the write with `Select`/`Omit`, is not reported. This maps to [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html).

This vulnerability class has been responsible for significant security incidents, including the 2012 GitHub mass-assignment vulnerability where an attacker added their SSH key to the Ruby on Rails organisation by exploiting unfiltered model binding.

**Severity:** Medium | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

Web frameworks that bind request bodies to structs are convenient for rapid development, but they create a hidden contract: every exported field in the target struct becomes a potential attack surface. Developers often reuse a single domain model struct for both internal operations (where fields like `IsAdmin` or `CreatedAt` are set by the system) and API request binding (where only a subset of fields should be writable by the user). When these two concerns are conflated, an attacker who reads the API documentation, examines a JavaScript bundle, or inspects network responses can identify internal field names and submit them in requests.

The impact depends on what privileged fields exist in the struct. Privilege escalation (`IsAdmin: true`), bypassing subscription paywalls (`IsPremium: true`), overwriting audit trails (`CreatedAt`), and injecting values into fields used in database queries or business logic are all observed real-world consequences. The vulnerability is particularly insidious because the exploit payload looks identical to a legitimate request — it simply includes additional JSON keys that the developer did not anticipate being set.

## What Gets Flagged

A request body bound into a value that is then saved whole:

```go
// FLAGGED: gin bind, then GORM create
var u models.User
if err := c.ShouldBindJSON(&u); err != nil { ... }
db.Create(&u)

// FLAGGED: bound map passed to Updates
_ = c.Bind(&input)
db.Model(&models.User{}).Where("id = ?", id).Updates(input)

// FLAGGED: decoder variable, then a repository save
dec := json.NewDecoder(r.Body)
if err := dec.Decode(acct); err != nil { ... }
s.store.Save(r.Context(), acct)

// FLAGGED: io.ReadAll + json.Unmarshal, then Mongo InsertOne
_ = json.Unmarshal(body, &u)
coll.InsertOne(r.Context(), u)

// FLAGGED: the whole bound value as a Mongo $set
if err := c.ShouldBind(&item); err != nil { ... }
s.items.UpdateOne(c, bson.M{"_id": id}, bson.M{"$set": item})
```

Not flagged: a request DTO whose fields are copied (`db.Create(&User{Name: in.Name})`), a write restricted with `Select(...)` or `Omit(...)`, a bound value that is only read, decoding `resp.Body` from an outgoing call, test files, comments and strings.

## Remediation

1. **Define separate Data Transfer Objects (DTOs) for API input** rather than reusing domain model structs. The DTO should contain only the fields a user is permitted to supply.

   ```go
   // SAFE: DTO exposes only user-writable fields
   type CreateUserRequest struct {
       Email    string `json:"email"    binding:"required,email"`
       Password string `json:"password" binding:"required,min=12"`
   }

   // Domain model with system fields; never bound directly from requests
   type User struct {
       ID        uint      `json:"id"`
       Email     string    `json:"email"`
       Password  string    `json:"-"`
       IsAdmin   bool      `json:"-"`  // set only by internal logic
       CreatedAt time.Time `json:"-"`
   }
   ```

2. **Use `json:"-"` and `binding:"-"` struct tags** to explicitly exclude fields that must never be accepted from external input, even on structs that are sometimes used for binding.

   ```go
   type User struct {
       Email   string `json:"email"   binding:"required"`
       IsAdmin bool   `json:"-"       binding:"-"` // excluded from binding
   }
   ```

3. **Validate that only expected fields are present** using `json.Decoder` with `DisallowUnknownFields()` to reject requests that supply unexpected keys.

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP API Security Top 10 – API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [CAPEC-63: Simple Script Injection](https://capec.mitre.org/data/definitions/63.html)
- [GitHub 2012 mass-assignment vulnerability write-up](https://github.com/blog/1068-public-key-security-vulnerability-and-mitigation)
- [Go encoding/json package documentation](https://pkg.go.dev/encoding/json)
