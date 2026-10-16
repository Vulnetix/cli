#define BIT(n) (1ULL << (n))
/* 1 << 40 is undefined for int, use 1ULL */
static const char *note = "x << 32";
int shifted(int x) { return 1 << 32 - 1; }
