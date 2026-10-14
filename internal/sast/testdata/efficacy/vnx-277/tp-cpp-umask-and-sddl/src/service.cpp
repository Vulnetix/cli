#include <sddl.h>
#include <sys/stat.h>
#include <windows.h>

class Service {
public:
	void start()
	{
~>		old_mask_ = ::umask(0000);
		open_spool();
	}

	bool share(PSECURITY_DESCRIPTOR *psd)
	{
		return ConvertStringSecurityDescriptorToSecurityDescriptorW(
~>			L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, psd, nullptr);
	}

private:
	mode_t old_mask_;
};
