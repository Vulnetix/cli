#include <signal.h>
#include <unistd.h>

int main(void) {
~>    signal(SIGSEGV, SIG_IGN);
    run_loop();
    return 0;
}
