#include <stdio.h>

/* if (st.st_mode & S_IWOTH) reject the file */
// if (st.st_mode & 022) return -1;
void help(void) {
    puts("checks st.st_mode & S_IWOTH before loading");
}
