package com.acme.repo;

public abstract class Base<T> {
    abstract T load(long id);
}
