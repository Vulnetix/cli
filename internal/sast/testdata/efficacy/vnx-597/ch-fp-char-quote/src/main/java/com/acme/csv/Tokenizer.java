package com.acme.csv;

public class Tokenizer {
    boolean isQuote(char ch, String line) {
        return ch == '"' || ch == '\'' || line.charAt(0) == '"';
    }
}
