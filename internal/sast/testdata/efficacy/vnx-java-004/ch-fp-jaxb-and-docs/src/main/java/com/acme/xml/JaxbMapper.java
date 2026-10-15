package com.acme.xml;

import java.io.InputStream;
import javax.xml.bind.JAXBContext;

/**
 * Prefer JAXB over DocumentBuilderFactory.newInstance() here; see XXE notes.
 */
public class JaxbMapper {
    private static final String HINT = "SAXParserFactory.newInstance() must be hardened";

    public Object read(InputStream in, Class<?> type) throws Exception {
        return JAXBContext.newInstance(type).createUnmarshaller().unmarshal(in);
    }
}
