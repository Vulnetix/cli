package com.example.feed;

import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.apache.commons.io.FileUtils;

public class Client {
    public InputStream get(String endpoint) throws Exception {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        return conn.getInputStream();
    }

    public void pull(URL remote, File dest) throws Exception {
        FileUtils.copyURLToFile(remote, dest, 5000, 10000);
    }
}
