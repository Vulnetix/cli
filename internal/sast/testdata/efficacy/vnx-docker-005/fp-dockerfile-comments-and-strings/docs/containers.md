# Containers

Never set `privileged: true` in a compose file:

```yaml
services:
  app:
    privileged: true
```
