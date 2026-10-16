#include <stdio.h>

struct account {
    char name[32];
    char shell[64];
    int uid;
};

int parse_account(const char *line, struct account *acct)
{
~>    if (sscanf(line, "%s %d %s", acct->name, &acct->uid, acct->shell) != 3) {
        return -1;
    }
    return 0;
}

int read_token(FILE *fp, char *token)
{
~>    return fscanf(fp, "%[^,],", token);
}
