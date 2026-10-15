package com.acme.auth;

import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.codec.digest.DigestUtils;

public class Sessions {
    public String open(HttpServletRequest request) {
~>        String sessionId = Long.toHexString(System.currentTimeMillis());
        return sessionId;
    }

    public String reset(HttpServletRequest request) {
~>        String resetToken = DigestUtils.md5Hex(request.getRemoteAddr() + new Date().getTime());
        return resetToken;
    }
}
