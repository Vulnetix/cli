#include <pwd.h>
#include <grp.h>
#include <unistd.h>

/* Runs the user's job as that user. If either call fails (RLIMIT_NPROC,
 * a missing capability), the job runs as root. */
int run_job_as(const struct passwd *pw, char *const argv[])
{
~>	setgid(pw->pw_gid);
~>	setuid(pw->pw_uid);
	return execv(argv[0], argv);
}

int parse_untrusted(const char *path)
{
~>	seteuid(getuid());
	return load_document(path);
}
