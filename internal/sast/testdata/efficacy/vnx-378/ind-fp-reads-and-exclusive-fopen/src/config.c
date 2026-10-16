#include <stdio.h>

int read_handoff(char *buf, size_t n)
{
    FILE *in = fopen("/tmp/handoff.json", "r");
    if (!in)
        return -1;
    fread(buf, 1, n, in);
    fclose(in);
    return 0;
}

int claim_handoff(void)
{
    FILE *out = fopen("/tmp/handoff.claim", "wx");
    if (!out)
        return -1;
    fclose(out);
    return 0;
}

int write_config(void)
{
    FILE *cfg = fopen("/etc/agent/agent.conf", "w");
    if (!cfg)
        return -1;
    fclose(cfg);
    return 0;
}
