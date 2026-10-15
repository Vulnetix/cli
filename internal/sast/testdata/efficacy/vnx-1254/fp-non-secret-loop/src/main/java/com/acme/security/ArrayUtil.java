package com.acme.security;

public final class ArrayUtil {
    public static boolean sameShape(int[] widths, int[] heights) {
        for (int i = 0; i < widths.length; i++) {
            if (widths[i] != heights[i]) return false;
        }
        return true;
    }

    public static int firstDifference(char[] left, char[] right) {
        for (int i = 0; i < left.length; i++) {
            if (left[i] != right[i]) {
                return i;
            }
        }
        return -1;
    }
}
