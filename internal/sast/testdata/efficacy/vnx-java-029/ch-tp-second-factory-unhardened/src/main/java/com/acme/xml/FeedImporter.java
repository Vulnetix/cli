package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import org.xml.sax.helpers.DefaultHandler;

public class FeedImporter {

    public Document parseFeed(InputStream in) throws Exception {
        DocumentBuilderFactory feedFactory = DocumentBuilderFactory.newInstance();
        feedFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return feedFactory.newDocumentBuilder().parse(in);
    }
    private int counter1;
    private int counter2;
    private int counter3;
    private int counter4;
    private int counter5;
    private int counter6;
    private int counter7;
    private int counter8;
    private int counter9;
    private int counter10;
    private int counter11;
    private int counter12;
    private int counter13;
    private int counter14;
    private int counter15;
    private int counter16;
    private int counter17;
    private int counter18;
    private int counter19;
    private int counter20;
    private int counter21;
    private int counter22;
    private int counter23;
    private int counter24;
    private int counter25;
    private int counter26;
    private int counter27;
    private int counter28;
    private int counter29;
    private int counter30;
    private int counter31;
    private int counter32;
    private int counter33;
    private int counter34;
    private int counter35;

    public void parseManifest(InputStream in, DefaultHandler handler) throws Exception {
~>        SAXParserFactory manifestFactory = SAXParserFactory.newInstance();
        manifestFactory.setNamespaceAware(true);
        SAXParser parser = manifestFactory.newSAXParser();
        parser.parse(in, handler);
    }
}
