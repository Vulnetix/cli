package com.acme.repo;

import java.util.Map;
import java.util.Optional;

public interface Store<K, V> {
    /**
     * Looks a value up.
     *
     * @param <K> key type
     * @param key the key
     * @param defaults fallback values
     * @return the value
     */
~>    Optional<V> get(K key, Map<String, ? extends V> fallback);

    /**
     * Removes everything.
     *
     * @return how many entries were removed
     */
~>    public abstract void clear();
}
