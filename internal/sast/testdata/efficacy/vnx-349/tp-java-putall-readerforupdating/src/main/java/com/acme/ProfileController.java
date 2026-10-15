package com.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class ProfileController {
    private final ObjectMapper mapper = new ObjectMapper();

    public Principal update(HttpServletRequest request, Principal principal) throws Exception {
~>        return mapper.readerForUpdating(principal).readValue(request.getInputStream());
    }

    public Map<String, Object> claims(HttpServletRequest request, Map<String, Object> claims) {
~>        claims.putAll(request.getParameterMap());
        return claims;
    }
}
