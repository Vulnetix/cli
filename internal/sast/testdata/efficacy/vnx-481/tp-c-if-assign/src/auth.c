int check(int uid, int *out)
{
~>    if (uid = 0) {
        return 1;
~>    } else if (out[0] = uid) {
        return 2;
    }
~>    if(*out=1)
        return 3;
    return 0;
}
