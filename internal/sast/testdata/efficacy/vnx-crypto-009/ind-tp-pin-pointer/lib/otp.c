#include <stdlib.h>
#include "otp.h"

int otp_issue_for_device(struct device *dev, unsigned int *pin)
{
    if (dev == NULL || pin == NULL)
        return -1;
~>    *pin = 100000u + (unsigned int)(rand() % 900000);
    dev->pending_pin_expires = now_s() + 300;
    return 0;
}
