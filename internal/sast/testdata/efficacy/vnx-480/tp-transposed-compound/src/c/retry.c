int backoff(int attempts, int step)
{
    int delay = 100;
~>    delay =- step;
    return delay * attempts;
}
