package com.acme.fetch;

import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class Downloader {
    // The URL is chosen by callers (scheduled sync jobs read it from configuration).
    public InputStream open(String location) throws Exception {
        return new URL(location).openStream();
    }

    public String who(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }
}
