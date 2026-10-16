package com.acme.fetch;

import javax.servlet.http.HttpServletRequest;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

public class Scrape {
    public Document title(HttpServletRequest req) throws Exception {
        String raw = req.getParameter("site");
        String site = raw.trim();
~>        return Jsoup.connect(site).get();
    }
}
