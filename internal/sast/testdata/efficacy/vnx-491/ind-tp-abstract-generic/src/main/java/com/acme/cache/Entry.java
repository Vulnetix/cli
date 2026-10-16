package com.acme.cache;

public abstract class Entry<K, V> implements Cloneable {
    protected K key;
    protected V value;

    @SuppressWarnings("unchecked")
    @Override
~>    public Entry<K, V> clone()
            throws CloneNotSupportedException {
        return (Entry<K, V>) super.clone();
    }

    public abstract long weight();
}
