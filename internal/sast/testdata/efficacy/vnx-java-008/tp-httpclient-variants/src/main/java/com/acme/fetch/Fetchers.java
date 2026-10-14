package com.acme.fetch;

import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import javax.servlet.http.HttpServletRequest;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.http.client.methods.HttpGet;
import org.jsoup.Jsoup;

public class Fetchers {
    public void fetch(HttpServletRequest req) throws Exception {
        String u = req.getParameter("u");
~>        HttpRequest r = HttpRequest.newBuilder(URI.create(u)).GET().build();
~>        HttpGet get = new HttpGet(u);
~>        Request ok = new Request.Builder().url(u).build();
~>        Jsoup.connect(req.getParameter("page")).get();
        String host = req.getParameter("host");
        int port = Integer.parseInt(req.getParameter("port"));
~>        Socket s = new Socket(host, port);
        HttpClient.newHttpClient().send(r, java.net.http.HttpResponse.BodyHandlers.ofString());
        s.close();
    }
}
