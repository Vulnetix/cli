---
title: "VNX-1047 – Modules with Circular Dependencies"
description: "Detects Python and JavaScript/TypeScript modules of the same project that import each other, directly or through a third module, including cycles hidden by an import deferred into a function."
---

## Overview

VNX-1047 resolves the imports of every Python and JavaScript/TypeScript file to files of the scanned tree and reports the modules that depend on each other in a cycle. This is [CWE-1047: Modules with Circular Dependencies](https://cwe.mitre.org/data/definitions/1047.html).

What is resolved:

- **Python**: `import a.b`, `from a.b import c` (including `c` as a submodule), `from .x import y`, `from ..x import y` and `from . import name`. An absolute import is resolved from every directory above the importer that is not itself a package, so `import json` inside a package is the standard library, not a local `json/` directory.
- **JavaScript/TypeScript**: `require('./x')`, `import ... from './x'`, `import './x'`, `export ... from './x'` and `import('./x')`, with the usual extension and `index` resolution, and `./x.js` in TypeScript source naming `./x.ts`.

What is reported:

- Two modules that import each other when they are loaded: once, on the import in the file whose path sorts first.
- Three modules in a load-time cycle: once, on the import made by the module whose path sorts first.
- An import moved into a function body that closes a cycle (of any length) with load-time imports back to the same module: on the deferred import. Deferring the import is the usual workaround; the dependency cycle is still there.

What is not reported: imports under `if TYPE_CHECKING:`, `import type` and import lists made only of `type` names, cycles in which every import is deferred, package and standard-library imports, path aliases (`@/x`), commented-out imports, and load-time cycles longer than three modules. Go is not covered: the Go compiler rejects import cycles.

**Severity:** Low | **CWE:** [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html)

## Why This Matters

When two modules import each other, whichever loads first sees the other only partially initialised. In Python that is an `ImportError: cannot import name ... (most likely due to a circular import)` or an attribute that is `None` at first use; in CommonJS it is an empty `exports` object; in ES modules it is a binding in its temporal dead zone. The objects affected are often exactly the ones that are set up once at import time: a logger, a validator, an authentication handler or a configuration object. A check that silently sees `undefined` is a check that does not run.

## What Gets Flagged

```python
# shop/billing.py
from shop.orders import Order, OrderStatus   # FLAGGED: shop/orders.py imports shop.billing back

# shop/orders.py
from shop.billing import charge
```

```python
# server/database.py
def init_db():
    import models          # FLAGGED: models.py imports database at load time
    Base.metadata.create_all(bind=engine)
```

```typescript
// lib/anti.ts
import { readFixes } from '../routes/fixes'   // FLAGGED: routes/fixes.ts -> lib/challenges.ts -> lib/anti.ts
```

## What Is Not Flagged

```python
if TYPE_CHECKING:
    from .server import Server   # type-only, never executed
```

```typescript
import type { Customer } from './customer'
import { type Address, type Region } from './customer'
```

## Remediation

1. Move the code both modules need into a third module that imports neither of them.
2. Invert one dependency: pass the object in (a parameter, a registration call) instead of importing it.
3. In TypeScript, import names used only as types with `import type`.
4. Do not hide a cycle by moving the import into a function; it keeps the coupling and moves the failure to the first call.

## References

- [CWE-1047: Modules with Circular Dependencies](https://cwe.mitre.org/data/definitions/1047.html)
- [Python: the import system](https://docs.python.org/3/reference/import.html)
- [Node.js: cycles in CommonJS modules](https://nodejs.org/api/modules.html#cycles)
