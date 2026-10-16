---
title: "VNX-1044 – Architecture with Number of Horizontal Layers Outside of Expected Range"
description: "Reports the concrete case of too few layers: an HTTP controller, view, route handler or servlet that executes SQL against the database itself, once per file, in Java, Python and JavaScript/TypeScript."
---

## Overview

[CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) is about an architecture with too many or too few horizontal layers. A layer count cannot be seen in one file, so VNX-1044 reports the case that can: the presentation layer talking to the database directly, with no data-access layer in between. It reports once per file, on the first such call.

What counts as the presentation layer:

- **Java**: a Spring `@Controller`/`@RestController`, a JAX-RS `@Path` resource, an `HttpServlet`, or a `*Controller`/`*Servlet` class.
- **Python**: a Django, Flask or FastAPI view or route module (`views.py`, `routes.py`, `views/` or `routes/` directories), or a module with `@app.route`, `@bp.route`, `@router.get` or `@api_view` handlers.
- **JavaScript/TypeScript**: a module in `routes/` or `controllers/`, or one that registers `app.get`/`router.post`-style handlers.

What counts as executing SQL:

- **Java**: `createStatement`, `prepareStatement`, `prepareCall`, `jdbcTemplate.query*`/`update`/`execute`, `createNativeQuery`, or `execute*` with a SQL literal.
- **Python**: `cursor`/`connection`/`db`/`session` `.execute*`, `get_db().execute`, `Model.objects.raw`, `pandas.read_sql`.
- **JavaScript/TypeScript**: `sequelize.query`, `knex.raw`, Prisma `$queryRaw`/`$executeRaw`, and `db`/`pool`/`connection`/`client` `.query`/`execute`/`run`/`all`/`get` with SQL text.

Parameterised and concatenated queries are both reported, because the defect is where the query lives, not how it is built. The injection rules judge how it is built.

Not reported: SQL in repository, DAO, model or service files; ORM query builders and repository methods called from a controller; SQL text that is only logged or quoted; test code, migrations and comments.

**Severity:** Low | **CWE:** [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html)

## Why This Matters

When request handling and query building sit in the same function, every handler writes its own SQL, so every handler can get it wrong. Injectable string building, a missing `WHERE owner_id = ?` authorisation filter or an unbounded `SELECT *` gets copied from one handler to the next. A data-access layer puts those queries in one place, where they can be reviewed and tested once.

## What Gets Flagged

```python
@bp.route("/orders/<int:order_id>")
def show(order_id):
    cur = get_db().cursor()
    cur.execute("SELECT id, total FROM orders WHERE id = %s", (order_id,))   # FLAGGED
```

```typescript
// routes/search.ts
models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)   // FLAGGED
```

```java
@RestController
public class ReportController {
    public List<Map<String, Object>> sales() {
        return jdbcTemplate.queryForList("SELECT region, SUM(total) FROM orders GROUP BY region");   // FLAGGED
    }
}
```

## What Is Not Flagged

```java
@Repository
public class OrderRepository {
    public List<Map<String, Object>> salesByRegion() {
        return jdbcTemplate.queryForList("SELECT region, SUM(total) FROM orders GROUP BY region");
    }
}
```

```python
def cheap(request):
    items = Product.objects.filter(price__lt=10)   # ORM call from a view
```

In a Python project that has a data manager module (a `models`, `repositories`, `dao`, `db` or similar module or directory), a view or route file whose first direct SQL call is raw database access (`sqlite3.connect()`, `cursor()`, `objects.raw()`, `cursor.execute()`, `db.execute("SELECT ...")`) is left to [VNX-1057](../vnx-1057/), which reports that line and every other raw access in the file for the same reason. This rule still reports such a file in a project with no data manager module.

## Remediation

1. Move the query into a repository, DAO or service function, and call that from the controller.
2. Give the data-access function a narrow signature (`find_order_for_user(user_id, order_id)`) so the authorisation filter is part of the query.
3. Use parameterised queries or the ORM inside the data-access layer.

## References

- [CWE-1044: Architecture with Number of Horizontal Layers Outside of Expected Range](https://cwe.mitre.org/data/definitions/1044.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
