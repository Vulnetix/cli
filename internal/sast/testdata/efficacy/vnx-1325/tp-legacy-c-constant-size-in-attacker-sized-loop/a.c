void f(char **argv) {
	int n = atoi(argv[1]);
	for (int i = 0; i < n; i++) {
~>		buffers[i] = malloc(4096);
	}
	char *after = malloc(64);
}
