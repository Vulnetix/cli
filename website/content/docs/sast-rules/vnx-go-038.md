---
title: "VNX-GO-038 – Potential mass assignment via struct binding"
description: "Detect Go code that binds or decodes request bodies directly into structs without field-level restrictions, enabling attackers to set privileged or internal fields that were not intended to be user-controlled."
---

## Overview

This rule flags Go code that calls `Bind`, `ShouldBind`, `Decode`, or `json.Unmarshal` with a source of `r.Body`, `r.Form`, `json.NewDecoder(r.Body)`, or equivalent request data, where the target struct does not use `binding:"-"` or `json:"-"` tags to exclude sensitive fields. Mass assignment (also called auto-binding or over-posting) occurs when a web framework automatically maps all request parameters to object fields, allowing an attacker to supply values for fields such as `IsAdmin`, `Role`, `Balance`, or `Verified` that the application never intended to accept from user input. This maps to [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html).

This vulnerability class has been responsible for significant security incidents, including the 2012 GitHub mass-assignment vulnerability where an attacker added their SSH key to the Ruby on Rails organisation by exploiting unfiltered model binding.

**Severity:** Medium | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html) | **OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Why This Matters

Web frameworks that bind request bodies to structs are convenient for rapid development, but they create a hidden contract: every exported field in the target struct becomes a potential attack surface. Developers often reuse a single domain model struct for both internal operations (where fields like `IsAdmin` or `CreatedAt` are set by the system) and API request binding (where only a subset of fields should be writable by the user). When these two concerns are conflated, an attacker who reads the API documentation, examines a JavaScript bundle, or inspects network responses can identify internal field names and submit them in requests.

The impact depends on what privileged fields exist in the struct. Privilege escalation (`IsAdmin: true`), bypassing subscription paywalls (`IsPremium: true`), overwriting audit trails (`CreatedAt`), and injecting values into fields used in database queries or business logic are all observed real-world consequences. The vulnerability is particularly insidious because the exploit payload looks identical to a legitimate request — it simply includes additional JSON keys that the developer did not anticipate being set.

## What Gets Flagged

The rule fires when request body data is decoded directly into a struct that may contain unexported-dangerous or system-managed fields.

```go
// FLAGGED: full User model bound directly from request body
type User struct {
    ID        int    `json:"id"`
    Email     string `json:"email"`
    IsAdmin   bool   `json:"is_admin"`   // should never come from user input
    CreatedAt string `json:"created_at"` // server-managed
}

func updateUser(w http.ResponseWriter, r *http.Request) {
    var user User
    // Attacker can set IsAdmin: true in the JSON body
    json.NewDecoder(r.Body).Decode(&user)
    db.Save(&user)
}

// FLAGGED: gin binding without exclusions
func createUser(c *gin.Context) {
    var user User
    c.ShouldBind(&user) // all exported fields are bindable
    database.Create(&user)
}
```

```go
// SAFE: dedicated request DTO with only user-writable fields
type UpdateUserRequest struct {
    Email       string `json:"email"        binding:"required,email"`
    DisplayName string `json:"display_name" binding:"max=100"`
    // IsAdmin deliberately absent — not accepted from user input
}

func updateUser(w http.ResponseWriter, r *http.Request) {
    var req UpdateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    // Apply only the permitted fields to the domain model
    user.Email = req.Email
    user.DisplayName = req.DisplayName
    db.Save(&user)
}
```

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
