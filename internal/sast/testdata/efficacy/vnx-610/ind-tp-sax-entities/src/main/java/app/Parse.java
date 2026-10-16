package app;

import javax.xml.parsers.*;
import org.xml.sax.*;

public class Parse {
    XMLReader reader() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        XMLReader reader = spf.newSAXParser().getXMLReader();
~>        reader.setFeature("http://xml.org/sax/features/external-general-entities", true);
~>        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        return reader;
    }
}
