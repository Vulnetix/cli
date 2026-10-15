double factor(char unit)
{
    double f;
~>    switch (unit)
    {
    case 'k':
        f = 1e3;
        break;
    case 'M':
        f = 1e6;
        break;
    }
    return f;
}
