#include <windows.h>
#include <tchar.h>

void Profile::SetHome(LPCTSTR home)
{
	TCHAR buf[MAX_PATH];
~>	_tcscpy(buf, home);
~>	lstrcatW(m_wide, m_suffix.c_str());
	::OutputDebugString(buf);
}

void Profile::Read()
{
	char line[128];
~>	gets (line);
}
