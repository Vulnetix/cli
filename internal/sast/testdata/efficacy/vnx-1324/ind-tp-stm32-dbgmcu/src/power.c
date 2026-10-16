#include "stm32f4xx.h"
void power_init(void)
{
    RCC->APB1ENR |= RCC_APB1ENR_PWREN;
~>    DBGMCU->CR |= DBGMCU_CR_DBG_STANDBY;
    PWR->CR |= PWR_CR_LPDS;
}
