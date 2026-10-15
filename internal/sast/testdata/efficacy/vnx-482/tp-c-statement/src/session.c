struct session { int authenticated; int retries; };

void logout(struct session *s)
{
~>    s->authenticated == 0;
    s->retries = 0;
}

void reset(int *count)
{
    if (*count > 10)
~>        count[0] == 0;
}
