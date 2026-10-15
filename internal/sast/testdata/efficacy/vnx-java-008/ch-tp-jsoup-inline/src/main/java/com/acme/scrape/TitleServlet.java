package com.acme.scrape;

import javax.servlet.http.HttpServletRequest;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

public class TitleServlet {
    public String title(HttpServletRequest request) throws Exception {
~>        Document doc = Jsoup.connect(request.getParameter("page")).get();
        return doc.title();
    }
}
