from typing import Any
Flags = int | str | bytes | None | float | list | dict | set | tuple | complex | bool | Any
PERM = READ | WRITE | EXEC | ADMIN | OWNER | GROUP | OTHER | STICKY | SETUID | SETGID | NOEXEC | SYNC
MSG = "a + b - c * d / e % f ** g & h | i ^ j << k >> l == m != n < o > p"  # a + b - c * d + e - f + g - h * i
