package com.acme.util;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.util.Scanner;

public class Text {
    // Socket socket = new Socket(host, port);  leaks unless closed
    private static final String DOC = "FileInputStream in = new FileInputStream(path);";

    public int first(byte[] data) {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        return in.read();
    }

    public String word() {
        Scanner sc = new Scanner(System.in);
        return sc.next();
    }

    public int peek(String s) throws Exception {
        StringReader r = new StringReader(s);
        return r.read();
    }
}
