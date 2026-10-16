#include <stdio.h>
#include <stdlib.h>

void run_post_upload_hook(const char *script, const char *uploaded_file)
{
	char cmd[512];

~>	snprintf(cmd, sizeof cmd, "%s '%s' --quarantine", script, uploaded_file);
	if (system(cmd) != 0)
		fprintf(stderr, "hook failed\n");
}
