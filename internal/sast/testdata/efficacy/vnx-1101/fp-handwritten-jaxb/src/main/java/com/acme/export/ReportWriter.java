package com.acme.export;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import java.io.Writer;

public class ReportWriter {

    public void write(Object report, Writer out) throws Exception {
        Marshaller m = JAXBContext.newInstance(report.getClass()).createMarshaller();
        m.marshal(report, out);
    }
}
