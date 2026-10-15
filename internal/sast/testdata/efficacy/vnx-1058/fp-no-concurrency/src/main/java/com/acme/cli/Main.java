package com.acme.cli;

import java.util.ArrayList;
import java.util.List;

public class Main {
    private static List<String> args = new ArrayList<>();
    private static int verbosity;

    public static void main(String[] argv) {
        for (String a : argv) {
            args.add(a);
            if (a.equals("-v")) {
                verbosity++;
            }
        }
    }
}
