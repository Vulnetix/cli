package com.acme.cli;

public class Main {
    public static void main(String[] args) {
~>        if (args != null & args[0].equals("--help")) {
            System.out.println("usage");
        }
    }
}
