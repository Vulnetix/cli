/* int *p = (int *)0x8000; is what we used to do */
// volatile uint32_t *r = (volatile uint32_t *)0x40020000;
static const char *msg = "do not write (int *)0x8000 in new code";
