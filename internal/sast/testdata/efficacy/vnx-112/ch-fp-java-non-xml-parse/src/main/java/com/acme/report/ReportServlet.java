package com.acme.report;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDate;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LocalDate from = LocalDate.parse(request.getParameter("from"));
        UUID owner = UUID.fromString(request.getParameter("owner"));
        String next = request.getParameter("next");
        URI back = URI.create(next);
        long limit = Long.parseLong(request.getParameter("limit"));
        writeXml(response, from, owner, limit, back);
    }

    private void writeXml(HttpServletResponse response, LocalDate from, UUID owner, long limit, URI back) {
        Transformer t = TransformerFactory.newInstance().newTransformer();
    }
}
