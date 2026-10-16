int read_all(int fd, char *buf, size_t len)
{
retry:
	/*
	 * Callers used to goto retry; here, but the loop below
	 * now handles EINTR itself.
	 */
	return read_loop(fd, buf, len); /* never goto retry; again */
}
