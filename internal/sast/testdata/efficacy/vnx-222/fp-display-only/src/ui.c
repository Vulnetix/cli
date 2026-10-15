#include <stdio.h>
#include <string.h>

void show_title(const char *title)
{
	char label[32];

	snprintf(label, sizeof(label), "%s", title);
	printf("[%s]\n", label);
	puts(label);
}

void copy_name(char *dst, const char *src)
{
	char tmp[64];
	strncpy(tmp, src, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	draw_text(tmp);
}
