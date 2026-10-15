package com.acme;

public class Grid {
    public int find(int[][] cells, int want, int rows) {
        int r = 0;
        outer:
        while (r < rows) {
            for (int c = 0; c < cells[r].length; c++) {
                if (cells[r][c] == want) {
                    break outer;
                }
            }
            r = r + 1;
        }
        return r;
    }

    public void spin(int n) {
        int k = 0;
        while (k < n) {
            if (Thread.interrupted()) {
                throw new IllegalStateException("interrupted");
            }
        }
    }
}
