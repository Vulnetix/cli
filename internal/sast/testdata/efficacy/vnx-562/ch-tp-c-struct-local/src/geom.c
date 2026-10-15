struct point { int x; int y; };

struct point *origin(void)
{
    struct point p = { 0, 0 };
~>    return &p;
}

int *counter_ptr(int start)
{
~>    return &start;
}
