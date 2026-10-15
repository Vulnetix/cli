int pick(int mode)
{
    int value;

    switch (mode) {
    case 1:
        value = 10;
        break;
    default:
        value = 0;
        break;
    }
    return value;
}

int clamp(int x)
{
    int r;
    if (x > 100)
        r = 100;
    else
        r = x;
    return r;
}
