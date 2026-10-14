package com.acme.http;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

public class Clients {
    public void build(HttpsURLConnection conn) throws Exception {
~>        conn.setHostnameVerifier((hostname, session) -> true);
~>        HostnameVerifier lax = (h, s) -> true;
~>        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> { return true; });
~>        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(ctx(), NoopHostnameVerifier.INSTANCE);
~>        HttpClients.custom().setSSLHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
~>        new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build();
~>        new SSLContextBuilder().loadTrustMaterial(null, (chain, authType) -> true).build();
~>        SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
    }

    private javax.net.ssl.SSLContext ctx() throws Exception {
        return javax.net.ssl.SSLContext.getDefault();
    }
}
