#include "stm32f4xx_hal.h"

static void Debug_Config(void)
{
#ifdef DEBUG
  DBGMCU->CR |= DBGMCU_CR_DBG_SLEEP | DBGMCU_CR_DBG_STOP;
#if USE_TRACE
  HAL_DBGMCU_EnableDBGStopMode();
#endif
  HAL_DBGMCU_EnableDBGStandbyMode();
#endif
}

static void Low_Power(void)
{
#if !defined(NDEBUG)
  HAL_DBGMCU_EnableDBGSleepMode();
#endif
#if defined(DEBUG_BUILD) && DEBUG_BUILD
  CoreDebug->DHCSR = 0xA05F0001;
#endif
}
