package com.acme;

public class Notes {
    // private DataSource dataSource;  dataSource.getConnection() used to NPE here
    /* private Cipher cipher; cipher.doFinal(x) */
    private static final String HELP = "private Foo foo; foo.bar() throws NullPointerException";

    public String help() {
        return HELP;
    }
}
