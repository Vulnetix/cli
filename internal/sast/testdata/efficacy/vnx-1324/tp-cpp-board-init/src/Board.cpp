#include "stm32l4xx_hal.h"

namespace board {

void Board::init() {
    HAL_Init();
~>    HAL_DBGMCU_EnableDBGSleepMode();
    clocks_.configure();
}

}  // namespace board
