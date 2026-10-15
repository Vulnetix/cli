package com.acme;

public class Config {
    static final Settings SETTINGS;

    static
    {
        try {
~>            SETTINGS = new Settings(
                    System.getenv("APP_HOME"));
        } catch (RuntimeException e) {
            throw new IllegalStateException("bad config", e);
        }
    }

    public static class Inner {
        private static Client client;
        static {
~>            client = new com.acme.http.Client();
        }
    }
}
