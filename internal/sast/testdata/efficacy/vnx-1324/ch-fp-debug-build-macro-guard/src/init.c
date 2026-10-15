#include "stm32f4xx_hal.h"

void platform_init(void)
{
    HAL_Init();
#ifdef DEBUG_BUILD
    HAL_DBGMCU_EnableDBGStopMode();
#endif
}
