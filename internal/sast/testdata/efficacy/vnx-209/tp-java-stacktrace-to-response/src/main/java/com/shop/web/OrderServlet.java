package com.shop.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][e]xc[e]pt[i]on[.]Ex[c]ep[t]io[n]Ut[i]ls@@;
import org.springframework.http.ResponseEntity;

public class OrderServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            render(request, response);
        } catch (Exception e) {
            response.setStatus(500);
~>            e.printStackTrace(response.getWriter());
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        try {
            save(request);
        } catch (Exception ex) {
~>            ex.printStackTrace(out);
        }
    }

    public ResponseEntity<String> export(String id) {
        try {
            return ResponseEntity.ok(exporter.run(id));
        } catch (Exception e) {
~>            return ResponseEntity.status(500).body(ExceptionUtils.getStackTrace(e));
        }
    }
}
