package com.acme.web;

import java.util.Iterator;

final class ReadOnlyIterator<T> implements Iterator<T> {
    private final Iterator<T> delegate;

    ReadOnlyIterator(Iterator<T> delegate) {
        this.delegate = delegate;
    }

    public boolean hasNext() { return delegate.hasNext(); }

    public T next() { return delegate.next(); }

    public void remove() {
        throw new UnsupportedOperationException("read-only");
    }

    public void setPassword(String password) {
        throw new UnsupportedOperationException("credentials are immutable");
    }
}
