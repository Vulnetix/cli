#include <stdlib.h>

int register_service(void)
{
~>    return system("sc.exe create AcmeAgent binPath= \"C:\\Program Files\\Acme Agent\\agent.exe\" start= auto");
}
