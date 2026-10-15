#include <filesystem>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <pathcch.h>

struct ctx { char *buf; };

std::string canonical_of(const std::string &p)
{
    return std::filesystem::canonical(p).string();
}

int with_room(const char *p)
{
    char resolved[PATH_MAX + 1];
    return realpath(p, resolved) ? 0 : -1;
}

int into_member(struct ctx *c, const char *p)
{
    return realpath(p, c->buf) ? 0 : -1;
}

int cwd_sized(void)
{
    char cwd[256];
    return getcwd(cwd, sizeof cwd) ? 0 : -1;
}

HRESULT canon_win(PWSTR out, PCWSTR in)
{
    WCHAR tmp[64];
    return PathCchCanonicalize(tmp, ARRAYSIZE(tmp), in);
}
