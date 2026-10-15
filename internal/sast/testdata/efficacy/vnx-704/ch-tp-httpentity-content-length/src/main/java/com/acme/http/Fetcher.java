package com.acme.http;

import java.io.IOException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

public class Fetcher {

    public byte[] body(HttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
~>        byte[] data = new byte[(int) entity.getContentLength()];
        entity.getContent().read(data);
        return data;
    }
}
