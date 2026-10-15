package com.lib;

import java.util.regex.Pattern;
import com.marklogic.xcc.Session;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

public class Gateway {
    private static final String BASE = "for $d in collection('docs')";

    Object fetch(CloseableHttpClient http, String baseUrl, String prefix) throws Exception {
        Pattern p = Pattern.compile("^" + prefix + "[a-z]+$");
        return http.execute(new HttpGet(baseUrl + "/v1/documents"));
    }

    Object constant(Session session) throws Exception {
        return session.submitRequest(session.newAdhocQuery(BASE + " return $d"));
    }
}
