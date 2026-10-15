#define MODE_FAST 2

int choose(int mode, int ret)
{
    if (mode == 1) {
        return 1;
~>    } else if (mode = MODE_FAST) {
        return 2;
    }
~>    if (ret = 0)
        return 3;
    return 0;
}
