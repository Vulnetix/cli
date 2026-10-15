package src;

import javax.servlet.http.HttpServletRequest;

class Reader {
	private static final int MAX = 64 * 1024;

	byte[] read(HttpServletRequest req) {
		int size = Integer.parseInt(req.getHeader("X-Size"));
		if (size > MAX) {
			throw new IllegalArgumentException("too large");
		}
		byte[] data = new byte[size];
		int n = Math.min(req.getContentLength(), MAX);
		char[] text = new char[n];
		return data;
	}
}
