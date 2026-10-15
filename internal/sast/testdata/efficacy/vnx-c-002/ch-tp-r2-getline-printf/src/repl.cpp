#include <cstdio>
#include <cstdlib>
#include <string>

int repl()
{
	char *line = NULL;
	size_t cap = 0;
	while (getline(&line, &cap, stdin) > 0) {
~>		std::printf(line);
	}
	const char *fmt = std::getenv("PROMPT_FMT");
~>	printf(fmt, 1);
	free(line);
	return 0;
}
