#include "stm32f1xx_hal.h"

void lock_debug_port(void)
{
    __HAL_AFIO_REMAP_SWJ_DISABLE();
    HAL_DBGMCU_DisableDBGSleepMode();
    HAL_DBGMCU_DisableDBGStopMode();
    DBGMCU->CR &= ~(DBGMCU_CR_DBG_STOP | DBGMCU_CR_DBG_STANDBY);
}
