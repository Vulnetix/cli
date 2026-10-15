package com.example.sort;

public interface Ordering<T> {
    int compare(T a, T b);

    /**
     * Indicates whether another ordering imposes the same order as this one.
     */
    @Override
    boolean equals(Object obj);
}
