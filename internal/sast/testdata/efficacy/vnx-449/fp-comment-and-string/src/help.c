#include <stdio.h>

/* MessageBox(h, "x", "y", MB_YESNO) == IDOK is a classic bug */
// if (MessageBox(h, "x", "y", MB_YESNO) == IDOK)
static const char *tip = "MessageBox(h, t, c, MB_YESNO) == IDOK never fires";

int main(void)
{
    puts(tip);
    return 0;
}
