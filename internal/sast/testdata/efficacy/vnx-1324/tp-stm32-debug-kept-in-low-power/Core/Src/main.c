#include "stm32f4xx_hal.h"

static void SystemPower_Config(void)
{
  /* keep the debugger attached through sleep and stop */
~>  DBGMCU->CR |= DBGMCU_CR_DBG_SLEEP | DBGMCU_CR_DBG_STOP | DBGMCU_CR_DBG_STANDBY;
~>  HAL_DBGMCU_EnableDBGStopMode();
~>  HAL_DBGMCU_EnableDBGStandbyMode( );
}

int main(void)
{
  HAL_Init();
  SystemPower_Config();
  while (1) {
    HAL_PWR_EnterSTOPMode(PWR_LOWPOWERREGULATOR_ON, PWR_STOPENTRY_WFI);
  }
}
