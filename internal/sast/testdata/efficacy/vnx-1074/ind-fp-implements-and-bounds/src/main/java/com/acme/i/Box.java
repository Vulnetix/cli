package com.acme.i;
public class Box<T extends Number> extends I8 {
    <U extends Comparable<U>> U pick(U a) { return a; }
}
