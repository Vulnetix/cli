package com.example.auth;

class TokenIssuerTest {
    private int counter = 0;

    String fakeToken() {
        String token = String.valueOf(++counter);
        return token;
    }
}
