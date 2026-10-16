#include "stm32f4xx.h"
void lock_down(void)
{
    HAL_DBGMCU_DisableDBGStopMode();
    CoreDebug->DHCSR = 0xA05F0000;
    MCUCR |= (1 << JTD);
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
