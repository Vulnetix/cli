package com.acme.report;

import java.sql.Connection;
import java.sql.DriverManager;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;

public class ReportJob {
    Connection open(String url) throws Exception {
~>        return @@sample:D[r]iv[e]rM[a]na[g]er[.]ge[t]Co[n]ne[c]ti[o]n@@(url, "reporting", "R3port!ng2023");
    }

    Authenticator mailAuth(final String user) {
        return new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
~>                return new PasswordAuthentication(user, "Mai1Relay#77".toCharArray());
            }
        };
    }
}
