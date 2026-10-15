#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    open_raw_socket();
~>    setgid(getgid());
~>    setuid(getuid());   /* give up root */
    return run(argc, argv);
}
