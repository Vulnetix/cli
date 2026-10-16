#include <stdio.h>
/* Do not call HAL_DBGMCU_EnableDBGStopMode() in release firmware. */
// DBGMCU->CR |= DBGMCU_CR_DBG_SLEEP is for bring-up only
static const char *hint = "run HAL_DBGMCU_EnableDBGSleepMode() to attach";
void show(void) { puts(hint); }
