package com.acme.cache;

class StubKey {
    @Override
    public boolean equals(Object o) {
        return o instanceof StubKey;
    }
}
