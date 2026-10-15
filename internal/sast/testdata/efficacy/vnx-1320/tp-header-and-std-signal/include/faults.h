#ifndef FAULTS_H
#define FAULTS_H
#include <signal.h>

static inline void ignore_math_faults(void)
{
~>	sigset(SIGFPE, SIG_IGN);
}
#endif
