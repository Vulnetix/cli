#include "stm32f4xx_hal.h"

void lock_debug(void)
{
    DBGMCU->CR &= ~(DBGMCU_CR_DBG_SLEEP | DBGMCU_CR_DBG_STOP | DBGMCU_CR_DBG_STANDBY);
    HAL_DBGMCU_DisableDBGStopMode();
    HAL_DBGMCU_DisableDBGStandbyMode();
    CoreDebug->DHCSR = 0xA05F0000;
    __HAL_AFIO_REMAP_SWJ_DISABLE();
    MCUCR |= (1 << JTD);
    MCUCR |= (1 << JTD);
    JTAG_ENABLE = 0;
    NRF_UICR->APPROTECT = UICR_APPROTECT_PALL_Enabled;
}
