#include "core_cm4.h"

void cycles_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

uint32_t cycles_now(void)
{
    uint32_t dhcsr = CoreDebug->DHCSR;
    return (dhcsr & CoreDebug_DHCSR_C_DEBUGEN_Msk) ? DWT->CYCCNT : 0;
}
