package com.example.feed;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class FeedReader {
    private final URL source;

    public FeedReader(URL source) {
        this.source = source;
    }

    public String read() throws Exception {
        try (BufferedReader r = new BufferedReader(
~>                new InputStreamReader(this.source.openStream(), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@))) {
            return r.readLine();
        }
    }

    public int size(String endpoint) throws Exception {
        URL url = new URL(endpoint);
~>        return url.openStream().available();
    }
}
