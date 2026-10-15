int pick(int a, int b)
{
    int r;
    if (a > b) {
        r = a;
    } else {
        r = b;
    }
    return r;
}

int mode_for(int k)
{
    int m;
    switch (k) {
    case 1:
        m = 0600;
        break;
    default:
        m = 0644;
        break;
    }
    return m;
}

int sign(int v)
{
    int s;
    if (v < 0) s = -1;
    else s = 1;
    return s;
}
