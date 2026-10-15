package com.shop.misc;

// @Entity
// public class Legacy {
public class EntityHelper {
    @Entity
    interface Marker {}

    @Override
    public String toString() { return "@Entity public class Foo {"; }

    @EntityListeners(Audit.class)
    public class Listener {
    }
}
