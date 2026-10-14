package com.acme.fetch;

import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import java.net.URL;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class JkuVerifier {
    @PostMapping("/verify")
    public boolean verify(@RequestParam("token") String token) throws Exception {
        var decoded = JWT.decode(token);
        var jku = decoded.getHeaderClaim("jku");
~>        var provider = new JwkProviderBuilder(new URL(jku.asString())).build();
        return provider.get(decoded.getKeyId()) != null;
    }
}
