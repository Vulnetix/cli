struct regs {
    unsigned int ctrl;
    unsigned int status;
};

void poke(void)
{
    unsigned int word;
~>    struct regs *r = ( struct regs * ) &word;
    r->status = 1;
}
