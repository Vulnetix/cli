package com.acme.doc;

import java.io.Serializable;

/**
 * Do not add a field like {@code private String password;} to a class that
 * implements Serializable without marking it transient.
 */
public class Notes implements Serializable {
    // private String apiKey;
    private String body = "private String token;";
}
