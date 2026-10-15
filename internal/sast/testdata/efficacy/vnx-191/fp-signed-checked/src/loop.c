/* memcpy(out, p, len - 4) without checking len wraps around */
int consume(int total, int used)
{
	int remain = total - used;
	if (remain <= 0)
		return 0;
	return remain;
}
