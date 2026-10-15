package com.acme.sync;

import org.apache.http.client.methods.HttpPost;

public class TokenClient {
    public HttpPost build(String basic) {
~>        HttpPost post = new HttpPost("http://sso.acme-corp.net/oauth/token");
        post.setHeader("Authorization", "Basic " + basic);
        return post;
    }
}
