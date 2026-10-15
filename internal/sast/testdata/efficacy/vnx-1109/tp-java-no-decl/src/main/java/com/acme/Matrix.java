package com.acme;

public class Matrix {
    public int sum(int[][] cells) {
        int r;
        int s = 0;
        for (r = 0; r < cells.length; r++) {
~>            for (r = 0; r < cells[0].length; r++) {
                s += cells[r][r];
            }
        }
        return s;
    }
}
