package com.acme.kdf;

public class KeyBox {
	private volatile byte[] key;

	public synchronized byte[] key() {
		if (key == null) {
			key = generate();
		}
~>		return key;
	}
}
