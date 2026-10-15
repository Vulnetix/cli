int run(struct machine *m)
{
top: m->pc = 0;
    while (step(m)) {
        if (m->reset)
~>            goto top;
    }
    return m->acc;
}
