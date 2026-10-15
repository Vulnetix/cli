int check(int ok, int *attempts)
{
    if (ok)
        return 0;
    else
        (*attempts)++;
~>        return -1;
}
