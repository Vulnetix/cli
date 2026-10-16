package com.acme;

public class Cmp {
    boolean has(Integer[] arr, int n) {
        Integer target = 5;
        for (int i = 0; i < n; i++) {
            if (target.equals(arr[i])) {
                return true;
            }
        }
        return false;
    }

    Long bump() {
        Long count = 0L;
        count++;
        return count;
    }
}
