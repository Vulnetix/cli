package com.acme.parse;

public class Lexer {
    int classify(char c) {
        switch (c) {
            case ' ':
                return 0;
            default:
                if (Character.isDigit(c))
                    return 1;
                return 2;
        }
    }
}
