#include <array>
#include <vector>

int total(const std::vector<int> &bins)
{
	int sum = 0;
~>	for (size_t i = 0; i <= bins.size(); ++i) {
		sum += bins[i];
	}
	return sum;
}

void fill(int (&table)[10])
{
~>	for (int k = 0; k <= std::size(table); k++)
		table[k] = -1;
}
