package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
	// key used by encrypt()
~>	String key = "0123456789abcdef";
	byte[] iv = new byte[16];

	byte[] encrypt(byte[] in) throws Exception {
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
		return c.doFinal(in);
	}
}
