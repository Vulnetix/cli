#include <stdio.h>

enum kind { KIND_FILE, KIND_DIR, KIND_LINK, KIND_SOCKET };

void print_kind(enum kind k)
{
    const char *name;
~>    switch (k) {
    case KIND_FILE:
        name = "file";
        break;
    case KIND_DIR:
        name = "directory";
        break;
    case KIND_LINK:
        name = "symlink";
        break;
    }
    printf("%s\n", name);
}
