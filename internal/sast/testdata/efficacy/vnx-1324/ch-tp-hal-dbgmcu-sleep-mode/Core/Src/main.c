#include "main.h"

static void SystemClock_Config(void);

int main(void)
{
  HAL_Init();
~>  HAL_DBGMCU_EnableDBGSleepMode();
  SystemClock_Config();
  while (1) {
    HAL_PWR_EnterSLEEPMode(PWR_MAINREGULATOR_ON, PWR_SLEEPENTRY_WFI);
  }
}
