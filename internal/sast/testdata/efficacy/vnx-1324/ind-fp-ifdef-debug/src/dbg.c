#include "stm32f4xx.h"
void dbg_init(void)
{
#ifdef DEBUG
    DBGMCU->CR |= DBGMCU_CR_DBG_SLEEP;
    HAL_DBGMCU_EnableDBGStopMode();
#endif
}
