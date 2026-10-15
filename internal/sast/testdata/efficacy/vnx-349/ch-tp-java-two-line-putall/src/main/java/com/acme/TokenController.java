package com.acme;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class TokenController {
    public Map<String, Object> refresh(HttpServletRequest request, Map<String, Object> verifiedClaims) {
        Map<String, String[]> params = request.getParameterMap();
~>        verifiedClaims.putAll(params);
        return verifiedClaims;
    }
}
