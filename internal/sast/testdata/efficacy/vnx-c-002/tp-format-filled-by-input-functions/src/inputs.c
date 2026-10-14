#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <readline/readline.h>

void from_inputs(FILE *fp, int sock, int id)
{
    char a[128], b[128], c[128], d[128], e[128];
    char *line = NULL;
    size_t cap = 0;
    const char *tmpl = secure_getenv("REPORT_TEMPLATE");
    char *answer;

~>    printf(tmpl, id);

    fgets(a, sizeof(a), fp);
~>    fprintf(stdout, a, id);

    recvfrom(sock, b, sizeof(b) - 1, 0, NULL, NULL);
~>    printf(b, id);

    fread(c, 1, sizeof(c) - 1, fp);
~>    printf(c, id);

    if (getline(&line, &cap, fp) > 0)
~>        printf(line, id);

    scanf("%127s", d);
~>    printf(d, id);

    gets(e);
~>    printf(e, id);

    answer = readline("> ");
~>    printf(answer, id);
}
