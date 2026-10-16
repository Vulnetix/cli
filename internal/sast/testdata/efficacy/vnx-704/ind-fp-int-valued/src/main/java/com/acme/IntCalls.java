package com.acme;

import java.util.List;

public class IntCalls {
    int a(String s) { return (int) s.length(); }
    int b(List<String> xs) { return (int) xs.stream().count(); }
    int c(double d) { return (int) Math.round(d); }
    // byte[] x = new byte[(int) file.length()];
    String note = "new byte[(int) file.length()]";
}
