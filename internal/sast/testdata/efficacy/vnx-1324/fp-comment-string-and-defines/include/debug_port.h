#ifndef DEBUG_PORT_H
#define DEBUG_PORT_H

/* Never ship with DBGMCU->CR |= DBGMCU_CR_DBG_STOP; or JTAG_ENABLE = 1 */
// HAL_DBGMCU_EnableDBGStopMode(); is for bring-up only
#define DBGMCU_CR_DBG_STOP_Pos (1U)
#define DBGMCU_CR_DBG_STOP     (0x1UL << DBGMCU_CR_DBG_STOP_Pos)

void HAL_DBGMCU_EnableDBGStopMode(void);
static const char *help = "set JTAG_ENABLE = 1 in the bring-up build";

#endif
