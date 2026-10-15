package com.acme.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedInputStream;
import java.io.ObjectInputStream;
import java.net.URLConnection;

public class SyncClient {
~>    private final ObjectMapper mapper = new ObjectMapper().enableDefaultTyping();

    public Object pull(URLConnection conn) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(
                new BufferedInputStream(conn.getInputStream()));
~>        return ois.readObject();
    }
}
