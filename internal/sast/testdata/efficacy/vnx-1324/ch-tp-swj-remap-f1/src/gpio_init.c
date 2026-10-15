#include "stm32f1xx_hal.h"

void gpio_init(void)
{
    __HAL_RCC_AFIO_CLK_ENABLE();
~>    __HAL_AFIO_REMAP_SWJ_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
}
