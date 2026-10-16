#include "led.h"

void led_apply(struct led *l, int mode)
{
    switch (mode) {
    case LED_OFF:
        l->duty = 0;
        break;
~>    default:
        l->duty = 50;
        l->blink = 1;
    case LED_ON:
        l->duty = 100;
        break;
    }
}
