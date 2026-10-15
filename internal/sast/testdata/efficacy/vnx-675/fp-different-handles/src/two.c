void two(FILE *in, FILE *out, int a, int b)
{
    fclose(in);
    fclose(out);
    close(a);
    close(b);
}

void sock(struct conn *c)
{
    close(c->fd);
    c->fd = -1;
    close(c->fd);
}
