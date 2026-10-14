package com.example.crypto;

public class Docs {
    // never write new SecretKeySpec("0123456789abcdef".getBytes(), "AES")
    /*
     * .signWith(SignatureAlgorithm.HS256, "secret") embeds the key in the jar
     */
    static final String HINT = "new SecretKeySpec(\"literal\".getBytes(), \"AES\") is insecure";
}
