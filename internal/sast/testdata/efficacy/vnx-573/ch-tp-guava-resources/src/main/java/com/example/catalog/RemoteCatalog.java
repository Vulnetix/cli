package com.example.catalog;

import com.google.common.io.Resources;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class RemoteCatalog {
    private final URL feed;

    public RemoteCatalog(String feedUrl) throws IOException {
        this.feed = new URL(feedUrl);
    }

    public String fetch() throws IOException {
~>        return Resources.toString(feed, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }

    public byte[] raw() throws IOException {
~>        return Resources.toByteArray(new URL("https://catalog.example.com/v1/all"));
    }
}
