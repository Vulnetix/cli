package com.acme.files;

import java.util.List;

public class Text {
    public int width(String s, List<String> rows, double scale) {
        int a = (int) (s.length() * scale);
        int b = (int) Math.round(scale);
        int c = (int) rows.stream().count();
        long millis = System.currentTimeMillis();
        int d = (int) (millis % 1000);
        char ch = (char) s.charAt(0);
        return a + b + c + d + ch + s.length();
    }
}

class Names {
    int sizes(String fileName, StringBuilder profile) {
        int a = (int) fileName.length();
        return a + (int) profile.length();
    }
}
