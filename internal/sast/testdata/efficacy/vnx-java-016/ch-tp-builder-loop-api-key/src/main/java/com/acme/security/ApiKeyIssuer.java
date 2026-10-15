package com.acme.security;

import java.util.Random;

public class ApiKeyIssuer {
    private static final String ALPHABET = "@@sample:A[B]CD[E]FG[H]JK[L]MN[P]QR[S]TU[V]WX[Y]Z2[3]45[6]78[9]@@";
    private final Random rnd = new Random(System.currentTimeMillis());

    public String issue(String clientId) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
~>            sb.append(ALPHABET.charAt(rnd.nextInt(ALPHABET.length())));
        }
        String apiKey = sb.toString();
        return clientId + ":" + apiKey;
    }
}
