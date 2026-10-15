#include "core_cm4.h"

static int debugger_attached(void)
{
    return (CoreDebug->DHCSR & CoreDebug_DHCSR_C_DEBUGEN_Msk) != 0;
}

void HardFault_Handler(void)
{
    if (CoreDebug->DHCSR & CoreDebug_DHCSR_C_DEBUGEN_Msk) {
        __BKPT(0);
    }
    while (1) {}
}
