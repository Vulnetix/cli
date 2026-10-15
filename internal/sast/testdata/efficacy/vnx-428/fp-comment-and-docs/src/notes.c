/*
 * CreateProcessA(NULL, "C:\\Program Files\\Acme Agent\\agent.exe", ...)
 * is how the old installer did it.
 */
// WinExec("C:\\Program Files\\Acme\\tray.exe", SW_HIDE);
static const char *kInstallDir = "C:\\Program Files\\Acme";
