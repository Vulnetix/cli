struct point {
    int x;
    int y;
};

int global_hits;

int tick(void)
{
    static int counter;
    counter++;
    global_hits++;
    return counter;
}
