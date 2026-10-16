package com.acme.game;

public class Board {
    private int[][] cells = new int[8][8];
    private static char[] adminPin = loadPin();

    public synchronized int[][] cells() {
~>        return cells;
    }

    public static char[] pin() {
~>        return adminPin;
    }

    private static char[] loadPin() {
        return System.getenv("PIN").toCharArray();
    }
}
