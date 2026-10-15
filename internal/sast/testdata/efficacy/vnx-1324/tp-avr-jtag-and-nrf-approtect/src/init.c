#include <avr/io.h>
#include <nrf.h>

void io_init(void)
{
    /* JTD must be written twice within four cycles */
~>    MCUCR &= ~(1 << JTD);
~>    MCUCR &= ~(1 << JTD);
}

void protect_init(void)
{
~>    NRF_UICR->APPROTECT = UICR_APPROTECT_PALL_HwDisabled;
~>    NRF_APPROTECT->DISABLE = APPROTECT_DISABLE_DISABLE_SwDisable;
}
