package com.acme.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class ClaimsController {
    private final ObjectMapper mapper = new ObjectMapper();

    public Map<String, Object> handle(HttpServletRequest request, Map<String, Object> verifiedClaims) throws Exception {
        Map<String, Object> claims = new HashMap<>(verifiedClaims);
~>        claims.putAll(request.getParameterMap());
        return claims;
    }

    public UserPrincipal update(HttpServletRequest request, UserPrincipal principal) throws Exception {
~>        return mapper.readerForUpdating(principal).readValue(request.getInputStream());
    }
}
