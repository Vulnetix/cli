#include <stdio.h>
/* snprintf(name, sizeof(path), ...) is the bug */
// strncpy(name, path, sizeof path);
static const char *tip = "fgets(name, sizeof(line), stdin)";
int main(void) { char name[8]; char line[64]; puts(tip); fgets(line, sizeof(line), stdin); return 0; }
