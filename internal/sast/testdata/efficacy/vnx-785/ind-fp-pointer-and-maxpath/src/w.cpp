#include <windows.h>
#include <shlwapi.h>

struct Ctx { char *out; };

bool f(Ctx *c, const char *in)
{
    char full[MAX_PATH];
    PathCanonicalizeA(full, in);
    PathCanonicalizeA(c->out, in);
    return true;
}
