package com.acme;

import org.apache.http.auth.*;
import org.apache.http.impl.client.BasicCredentialsProvider;

public class Http {
    BasicCredentialsProvider build(String user, String pass) {
        BasicCredentialsProvider p = new BasicCredentialsProvider();
~>      p.setCredentials(AuthScope.ANY, new NTCredentials(user, pass, "host01", "CORP"));
        return p;
    }
}
