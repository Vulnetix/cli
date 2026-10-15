#include "core_cm4.h"

void boot_enable_halting_debug(void)
{
~>    CoreDebug->DHCSR = 0xA05F0001;
}

void boot_enable_debug_msk(void)
{
~>    CoreDebug->DHCSR |= CoreDebug_DHCSR_C_DEBUGEN_Msk;
}
