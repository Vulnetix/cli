#include <stdint.h>
#include "core_cm4.h"
void boot_late_init(void)
{
    configure_clocks();
~>    CoreDebug->DHCSR = 0xA05F0001;
    start_app();
}
