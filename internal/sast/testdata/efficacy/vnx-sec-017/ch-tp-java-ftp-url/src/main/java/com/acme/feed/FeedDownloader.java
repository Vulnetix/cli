package com.acme.feed;

import java.net.URL;

public class FeedDownloader {
~>    private static final String FEED = "ftp://files.vendordata.com/export/daily.csv";

    public URL feedUrl() throws Exception {
        return new URL(FEED);
    }
}
