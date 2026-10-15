package com.acme.auth;

public class KeyRing<K> {
	private byte[] masterKey;

~>	protected class Entry<V> implements Comparable<Entry<V>> {
		V value;

		byte[] unwrap() {
			return Crypto.decrypt(masterKey, value);
		}

		public int compareTo(Entry<V> o) { return 0; }
	}
}
