#define LEN 16

char names[LEN];
int matrix[LEN][LEN];

void f(char name[LEN])
{
    /* name[LEN] would be one past the end */
    puts("buf[sizeof(buf)] is a bug");
    char copy[LEN];
    (void)copy;
}
