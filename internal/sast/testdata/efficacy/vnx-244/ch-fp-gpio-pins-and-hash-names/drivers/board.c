#include <stdlib.h>

void board_teardown(struct board *b)
{
    free(b->gpio_pin);
    free(b->led_pin);
    free(b->reset_pin);
    free(b->password_hash);
    free(b->secret_name);
    free(b->key_table);
    free(b->token);
    delete_pin_mapping(b);
}
