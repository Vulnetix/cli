struct pair { int a; int b; };

int first(void)
{
    double d = 1.0;
~>    return ((struct pair *)&d)->a;
}
