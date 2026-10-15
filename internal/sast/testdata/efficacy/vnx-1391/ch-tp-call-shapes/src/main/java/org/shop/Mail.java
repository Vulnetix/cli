package org.shop;

import java.util.Properties;

public class Mail {
    Properties smtp(javax.sql.DataSource unused) {
        Properties p = new Properties();
        p.put("mail.smtp.user", "orders");
~>        p.put("@@sample:m[a]il[.]sm[t]p[.][p]as[s]wo[r]d@@", "12345678");
        return p;
    }

    void pool(@@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][d]bc[p]2[.][B]as[i]cD[a]ta[S]ou[r]ce@@ ds) {
~>        ds.setPassword( "qwerty123" );
    }
}
