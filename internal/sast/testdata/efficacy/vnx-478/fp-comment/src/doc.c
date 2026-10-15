/*
 * Example of the bug this project avoids:
 *     int x;
 *     switch (k) { case 1: x = 1; break; }
 *     return x;
 */
// switch (k) { case 1: x = 1; }
int ok(void) { return 0; }
