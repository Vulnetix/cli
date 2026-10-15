package com.acme.kdf;

public class Vault {
    private final char[] password;
    private int[][] grid = new int[4][4];

    public Vault(char[] pw) { this.password = pw.clone(); }

~>    public char[] getPassword() { return password; }

    public int[][] getGrid() {
~>        return grid;
    }
}
