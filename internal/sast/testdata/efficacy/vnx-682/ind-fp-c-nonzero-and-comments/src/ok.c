int f(int hits, int d)
{
    // return hits / 0;
    /* x %= 0; */
    const char *msg = "never write hits / 0";
    float r = 1.5f / 0.0f;
    int a = hits / 10;
    int b = hits % 100;
    int c = hits / d;
    return a + b + c + (int)r;
}
