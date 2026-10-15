#include <unistd.h>

static void reset_cwd(void)
{
    chdir("/");
}

int enter(const char *dir)
{
~>    if (chroot(dir) < 0)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    reset_cwd();
    return enter(argv[1]);
}
