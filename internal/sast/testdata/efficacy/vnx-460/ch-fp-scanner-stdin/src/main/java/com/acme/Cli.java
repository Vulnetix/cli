package com.acme;

import java.util.Scanner;

public class Cli {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String name = sc.nextLine();
        System.out.println("hello " + name);
        sc.close();
    }

    static int parse(String line) {
        Scanner tokens = new Scanner(line);
        int v = tokens.nextInt();
        tokens.close();
        return v;
    }
}
