package com.acme.crypto;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

~>public class Vault<T extends Comparable<T>> implements Cloneable, Iterable<T> {
    private SecretKey masterKey;
    private Map<String, T> entries = new HashMap<>();

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public java.util.Iterator<T> iterator() {
        return entries.values().iterator();
    }
}
