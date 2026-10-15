int poll_once(int state)
{
~>    if(state=1)
        return 1;
~>    while (state = 2) {
        state--;
    }
    return 0;
}
