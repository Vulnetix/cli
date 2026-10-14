class A {
	void f() throws Exception {
~>		MessageDigest md = MessageDigest.getInstance("MD5");
		MessageDigest ok = MessageDigest.getInstance("SHA-256");
	}
}
