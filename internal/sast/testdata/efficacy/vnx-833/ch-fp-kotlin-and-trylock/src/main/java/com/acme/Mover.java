package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Mover {
    private final ReentrantLock src = new ReentrantLock();
    private final ReentrantLock dst = new ReentrantLock();

    public boolean move() {
        if (src.tryLock()) {
            try {
                if (dst.tryLock()) {
                    try { return copy(); } finally { dst.unlock(); }
                }
            } finally {
                src.unlock();
            }
        }
        return false;
    }

    public boolean back() {
        if (dst.tryLock()) {
            try {
                if (src.tryLock()) {
                    try { return copy(); } finally { src.unlock(); }
                }
            } finally {
                dst.unlock();
            }
        }
        return false;
    }

    private boolean copy() { return true; }
}
