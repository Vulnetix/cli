#include <windows.h>
#include <string>

bool SpawnAgent(STARTUPINFOW &si, PROCESS_INFORMATION &pi)
{
    std::wstring cmdline = L"C:\\Program Files\\Acme Agent\\agent.exe --tray";
~>    return CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, FALSE,
                          0, nullptr, nullptr, &si, &pi) != 0;
}

bool SpawnWorker(STARTUPINFOW &si, PROCESS_INFORMATION &pi)
{
    std::wstring line(L"C:\\Program Files\\Acme\\worker.exe");
~>    return CreateProcessW(NULL, line.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) != 0;
}
