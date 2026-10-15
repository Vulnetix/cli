package com.example;

import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][d]bc[p]2[.][B]as[i]cD[a]ta[S]ou[r]ce@@;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

public class ServerSetup {
    public BasicDataSource pool(String url) {
        BasicDataSource ds = new BasicDataSource();
        ds.setUrl(url);
~>        ds.setMaxTotal( 2 );
        return ds;
    }

    public Server jetty() {
~>        QueuedThreadPool threads = new QueuedThreadPool(2);
        return new Server(threads);
    }

    public void tomcat(@@sample:o[r]g[.][a]pa[c]he[.]co[y]ot[e][.]h[t]tp[1]1[.][H]tt[p]11[N]io[P]ro[t]oc[o]l@@ protocol) {
~>        protocol.setMaxThreads(1);
    }
}
