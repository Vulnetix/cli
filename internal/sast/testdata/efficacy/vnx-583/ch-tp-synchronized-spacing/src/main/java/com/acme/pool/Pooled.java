package com.acme.pool;

public class Pooled {
    @Override
~>    synchronized public void finalize ( ) {
        Pool.giveBack(this);
    }
}
