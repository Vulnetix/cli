struct Widget { int a; };

void use()
{
    Widget *w = new Widget;
    w->a = 3;
~>    delete[] w;
}
