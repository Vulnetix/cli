void a()
{
    int values[16];
    values[0] = 1;
~>    delete[] values;
}

void b()
{
    int x = 4;
~>    delete &x;
}
