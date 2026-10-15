/* if (fd = open(path, O_RDONLY) < 0) assigns the comparison result */
// flags & O_NONBLOCK == 0 tests flags & (O_NONBLOCK == 0)
static const char *kTip = "if (fd = open(path, O_RDONLY) < 0) is a bug";
