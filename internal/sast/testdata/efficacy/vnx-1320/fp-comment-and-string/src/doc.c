/* Never call signal(SIGSEGV, SIG_IGN): the fault would be lost. */
// ioctl(fd, WDIOC_SETOPTIONS, WDIOS_DISABLECARD) stops the watchdog
static const char *help = "signal(SIGSEGV, SIG_IGN) hides crashes";
