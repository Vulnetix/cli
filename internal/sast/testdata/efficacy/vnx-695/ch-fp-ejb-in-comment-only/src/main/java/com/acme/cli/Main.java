package com.acme.cli;

// Unlike a javax.ejb @Stateless bean, a command-line tool may exit directly.
public class Main {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.exit(2);
        }
        new Thread(() -> System.out.println(args[0])).start();
    }
}
