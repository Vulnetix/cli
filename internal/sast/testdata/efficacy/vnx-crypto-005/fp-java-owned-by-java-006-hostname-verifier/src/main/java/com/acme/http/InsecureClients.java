package com.acme.http;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import okhttp3.OkHttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContexts;

public class InsecureClients {

    public static void disableHostCheck() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    static final HostnameVerifier ALL_HOSTS = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    public static SSLConnectionSocketFactory apache() throws Exception {
        SSLContext ctx = SSLContexts.custom()
            .loadTrustMaterial(null, new TrustAllStrategy())
            .build();
        return new SSLConnectionSocketFactory(ctx, NoopHostnameVerifier.INSTANCE);
    }

    public static SSLContext lambdaTrust() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, (chain, authType) -> true).build();
    }

    public static OkHttpClient okhttp(OkHttpClient.Builder b) {
        return b.hostnameVerifier((host, sess) -> true).build();
    }

    public static Object netty() throws Exception {
        return SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
    }
}
