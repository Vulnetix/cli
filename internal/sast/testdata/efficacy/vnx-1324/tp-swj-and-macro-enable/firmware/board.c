#include "stm32f1xx_hal.h"
#include "board.h"

void board_init(void)
{
    __HAL_RCC_AFIO_CLK_ENABLE();
~>    __HAL_AFIO_REMAP_SWJ_ENABLE();
~>    JTAG_ENABLE = 1;
~>    swd_enabled = true;
}
