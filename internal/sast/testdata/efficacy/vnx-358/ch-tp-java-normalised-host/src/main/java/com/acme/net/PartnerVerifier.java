package com.acme.net;

import java.util.Locale;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import androidx.annotation.NonNull;

public final class PartnerVerifier implements HostnameVerifier {

    @Override
    public boolean verify(@NonNull String hostname, @NonNull SSLSession session) {
~>        return hostname.toLowerCase(Locale.ROOT).endsWith(".partner-api.com");
    }
}
