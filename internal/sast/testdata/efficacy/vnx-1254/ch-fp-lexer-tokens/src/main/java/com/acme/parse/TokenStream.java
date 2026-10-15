package com.acme.parse;

public class TokenStream {
    private final int[] tokens;

    public TokenStream(int[] tokens) {
        this.tokens = tokens;
    }

    public boolean startsWith(int[] expectedTokens) {
        for (int i = 0; i < expectedTokens.length; i++) {
            if (tokens[i] != expectedTokens[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean sameKeys(int[] keys, int[] otherKeys) {
        for (int i = 0; i < keys.length; i++) {
            if (keys[i] != otherKeys[i]) return false;
        }
        return true;
    }
}
