package com.acme.export;

import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

public class ExportService {

    private final JAXBContext context;

    public ExportService(JAXBContext context) {
        this.context = context;
    }

    // Serialises the report object; callers pass beans built from the
    // auto-generated schema classes in the catalog module.
    public String export(Object report) throws Exception {
        Marshaller m = context.createMarshaller();
        StringWriter out = new StringWriter();
        m.marshal(report, out);
        return out.toString();
    }
}
