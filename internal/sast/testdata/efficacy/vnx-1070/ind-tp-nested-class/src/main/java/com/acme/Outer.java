package com.acme;
import java.io.Serializable;
import java.io.Writer;
import java.net.http.HttpClient;
public class Outer {
    private Writer notSerializableOwner;
    public static class Inner implements Serializable {
        private int n;
~>        private HttpClient client = HttpClient.newHttpClient();
~>        private Writer out;
    }
}
