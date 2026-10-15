double scale(int a, double b)
{
    double inf = b / 0.0;
    int s = a / 0x10;
    float h = (float)a / 0.5f;
    int t = a / 10;
    const char *dev = "/dev/0";
    return inf + s + h + t + (dev != 0);
}
