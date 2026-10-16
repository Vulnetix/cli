#include <stdint.h>
#include "unity.h"

void test_gpio_writes_register(void)
{
    volatile uint32_t *fake = (volatile uint32_t *)0x20001000;
    *fake = 0;
    TEST_ASSERT_EQUAL_UINT32(0, *fake);
}
