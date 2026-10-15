package com.acme.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class RatesClient {
    private final ObjectMapper mapper = new ObjectMapper();

    // Parses the XML the bank's own feed returns, not anything a caller sent.
    public Document rates() throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(getClass().getResourceAsStream("/rates.xml"));
    }

    public Settings settings(HttpServletRequest request) throws Exception {
        return mapper.readValue(request.getInputStream(), Settings.class);
    }
}
