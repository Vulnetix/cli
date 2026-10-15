package com.example;

import java.io.File;
import java.util.List;

public class Safe {
    int ok(File f, List<String> items, String s) {
        int size = Math.toIntExact(f.length());
        long len = f.length();
        int n = (int) items.size();
        int k = (int) s.length();
        int ratio = (int) (len / 1024);
        return size + n + k + ratio;
    }
}
