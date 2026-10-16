package com.acme.hr;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class PayrollExport {
    public InputStream fetch() throws Exception {
~>        URL url = new URL("http://legacy.payroll-partner.com/export/employees.csv");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        return conn.getInputStream();
    }
}
