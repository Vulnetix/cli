package com.acme.fn;

@FunctionalInterface
public interface ThrowingSupplier<T> {
    T get() throws Exception;
}
