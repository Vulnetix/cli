#include <stddef.h>

int find_pair(const int *a, size_t n, int target)
{
	size_t i;
	for (i = 0; i < n; i++) {
		if (a[i] == target) {
			for (i = 0; i < n; i++)
				a_mark(i);
			break;
		}
	}
	return (int)i;
}
