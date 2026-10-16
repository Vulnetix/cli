int Parser::next()
{
again:
    int c = in_.get();
    if (c == '#') {
        while (c != '\n' && c != EOF) c = in_.get();
~>        goto again;
    }
    return c;
}
