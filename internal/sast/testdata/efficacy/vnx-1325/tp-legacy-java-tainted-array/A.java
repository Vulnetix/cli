class A {
	void f(HttpServletRequest req) {
		int n = Integer.parseInt(req.getParameter("n"));
~>		byte[] b = new byte[n];
		byte[] fixed = new byte[1024];
	}
}
