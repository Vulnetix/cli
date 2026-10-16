package com.acme.text;

public class Prefix {
    static boolean sameWord(String left, String right) {
        for (int i = 0; i < left.length(); i++) {
            if (left.charAt(i) != right.charAt(i)) return false;
        }
        return true;
    }

    // for (...) { if (storedToken[i] != presented[i]) return false; }
}
