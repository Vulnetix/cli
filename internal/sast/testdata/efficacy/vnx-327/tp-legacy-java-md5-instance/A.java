class A {
	byte[] f(String password) throws Exception {
~>		MessageDigest md = MessageDigest.getInstance("MD5");
		MessageDigest ok = MessageDigest.getInstance("SHA-256");
		return md.digest(password.getBytes());
	}
}
