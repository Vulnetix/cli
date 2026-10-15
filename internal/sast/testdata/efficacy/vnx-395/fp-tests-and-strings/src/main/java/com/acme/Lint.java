package com.acme;

public class Lint {
    // Do not write catch (NullPointerException e); check for null instead.
    static final String RULE = "catch (NullPointerException e) is forbidden";

    static class NullPointerExceptionMapper {
        String map(Throwable t) {
            return t instanceof NullPointerException ? "null" : "other";
        }
    }
}
