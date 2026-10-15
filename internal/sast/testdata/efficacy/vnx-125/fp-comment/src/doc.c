/*
 * for (i = 0; i <= sizeof(key); i++) reads one past the end.
 */
// n = read(fd, buf, sizeof(buf)); strlen(buf);
static const char *msg = "for (i = 0; i <= N; i++) x[i]";
