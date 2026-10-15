#include "board.hpp"
#include "@@sample:s[t]m3[2]l4[x]x[_][l]l[_][s]ys[t]em[.]h@@"

void Board::init()
{
    clocks_.configure();
~>    LL_DBGMCU_EnableDBGStopMode();
~>    LL_DBGMCU_EnableDBGStandbyMode();
    leds_.init();
}
