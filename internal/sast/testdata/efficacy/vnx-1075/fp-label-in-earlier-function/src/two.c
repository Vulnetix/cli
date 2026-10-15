int first(int x) {
    if (x < 0)
        goto out;
    x *= 2;
out:
    return x;
}

int second(int y) {
    if (y > 100)
        goto out;
    y += 1;
out:
    return y;
}
