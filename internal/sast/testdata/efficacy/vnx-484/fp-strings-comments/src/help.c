/*
 * case 1:
 *     do_thing();
 * case 2:
 */
static const char *usage = "case 1: do this\ncase 2: do that";
// case 3: forgotten break would be bad
int noop(void) { return 0; }
