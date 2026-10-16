#include <windows.h>
#include <string>

void HandleDelete(HANDLE hPipe, const std::string &path)
{
~>    ImpersonateNamedPipeClient(hPipe);
    DeleteFileA(path.c_str());
    RevertToSelf();
}
