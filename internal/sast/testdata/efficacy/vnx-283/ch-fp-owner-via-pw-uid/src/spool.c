#include <pwd.h>
#include <sys/stat.h>

int spool_dir_ok(const char *dir, const char *service_user)
{
    struct stat info;
    struct passwd *pw = getpwnam(service_user);
    if (pw == NULL || stat(dir, &info) != 0)
        return 0;
    if (info.st_uid != pw->pw_uid)
        return 0;
    return (info.st_mode & S_IWOTH) == 0;
}
