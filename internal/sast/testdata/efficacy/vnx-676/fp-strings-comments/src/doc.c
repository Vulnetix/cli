/* Never call gets(buf) or strcpy(dst, src). */
// sprintf(out, "%s", s);
static const char *banned = "gets( strcpy( strcat( sprintf(";
/*
    strcpy(dst, src);
*/
void noop(void) {}
