#define CHECK(x) \
    if (!(x)) \
        abort(); \
        log_fail();

int f(int a, int b)
{
    if (a > 0 &&
        b > 0)
        a = b;
    if (a)
        a = call(a,
                 b);
        b = 2;
    return a;
}
