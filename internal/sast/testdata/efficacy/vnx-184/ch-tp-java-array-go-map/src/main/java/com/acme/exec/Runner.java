package com.acme.exec;

public class Runner {
~>    private static final String[] BAD_CHARS = {";", "|", "&", "$("};

    public String run(String arg) throws Exception {
        for (String c : BAD_CHARS) {
            if (arg.contains(c)) {
                throw new IllegalArgumentException("bad input");
            }
        }
        return exec("convert " + arg);
    }
}
