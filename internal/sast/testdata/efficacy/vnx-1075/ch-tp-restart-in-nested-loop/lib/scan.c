static int scan_table(struct table *t)
{
	int i, j;

	restart:
	for (i = 0; i < t->rows; i++) {
		for (j = 0; j < t->cols; j++) {
			if (t->cells[i][j].stale) {
				refresh(t);
~>				goto restart ;
			}
		}
	}
	return 0;
}
