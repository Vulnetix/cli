typedef struct {
    int a;
} item_t;

void f(void)
{
    item_t it;
    item_t *p = (item_t *)&it;
    char raw[8];
    item_t *q = (item_t *)raw;
    (void)p; (void)q;
}
