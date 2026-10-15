package com.acme.util;

import java.io.Serializable;
import java.util.Comparator;
import java.util.function.Function;

public class Keys<T extends Serializable> implements Comparator<Serializable> {
    public int compare(Serializable a, Serializable b) {
        return 0;
    }
}

class KeyFn implements Function<String, Serializable> {
    public Serializable apply(String s) {
        return s;
    }
}

interface Identified extends Serializable {
    String id();
}
