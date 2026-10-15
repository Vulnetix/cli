int next_id(void)
{
    static int counter;
    counter++;
    return counter;
}
