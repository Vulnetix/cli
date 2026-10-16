package com.acme.feed;

import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class FeedIngestServlet extends HttpServlet {
    private static final XMLInputFactory FACTORY = XMLInputFactory.newFactory();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        InputStream in = request.getInputStream();
        try {
~>            XMLStreamReader reader = FACTORY.createXMLStreamReader(in);
            while (reader.hasNext()) {
                if (reader.next() == XMLStreamReader.START_ELEMENT && "item".equals(reader.getLocalName())) {
                    FeedStore.add(reader.getAttributeValue(null, "id"));
                }
            }
        } catch (XMLStreamException e) {
            response.sendError(400);
        }
    }
}
