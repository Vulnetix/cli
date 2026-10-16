package com.acme;

import java.io.BufferedReader;

public class Reader {
    public String slurp(BufferedReader in) throws Exception {
        String text = "";
        String line;
        while ((line = in.readLine()) != null) {
~>            text = text + line + "\n";
        }
        return text;
    }
}
