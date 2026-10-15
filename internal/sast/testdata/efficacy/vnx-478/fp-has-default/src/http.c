const char *reason(int code)
{
    const char *text;
    switch (code) {
    case 200:
        text = "OK";
        break;
    default:
        text = "Unknown";
        break;
    }
    return text;
}

int kind(int c)
{
    int k;
    switch (c) {
    case 'a': k = 1; break;
    case 'b': k = 2; break;
    default: return -1;
    }
    return k;
}
