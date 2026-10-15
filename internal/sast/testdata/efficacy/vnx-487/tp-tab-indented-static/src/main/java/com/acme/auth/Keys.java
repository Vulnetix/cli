package com.acme.auth;

class Keys {
~>	static String adminPassword = System.getenv("ADMIN_PW");
~>	SecretKey sessionKey;
	private PrivateKey hidden;
}
