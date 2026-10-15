#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct session { char user[32]; wchar_t wpath[260]; };

void session_open(struct session *s, const char *user, const wchar_t *dir, const wchar_t *leaf)
{
	char banner[64];
~>	(void) strcpy(s->user, user);
	wcscpy(s->wpath, L"C:\\data\\");
~>	wcscat(s->wpath, dir);
~>	wcscat(s->wpath, leaf);
~>	sprintf(banner,
	        "welcome back, %s", user);
	puts(banner);
}

int load_profile(FILE *fp)
{
	char name[40];
	int age;
~>	return fscanf(fp, "%s %d", name, &age);
}
