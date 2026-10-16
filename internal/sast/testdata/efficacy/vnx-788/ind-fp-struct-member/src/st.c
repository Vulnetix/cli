struct pkt { char data[16]; int len; };

void fill(struct pkt *p, int n)
{
    // runtime bound, array declared elsewhere
    p->data[n] = 0;
    /* name[sizeof(name)] = 0; */
}
