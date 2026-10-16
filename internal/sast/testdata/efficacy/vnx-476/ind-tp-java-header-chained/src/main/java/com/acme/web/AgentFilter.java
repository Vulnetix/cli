package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class AgentFilter {
    public boolean isBot(HttpServletRequest request) {
~>        String ua = request.getHeader("User-Agent").toLowerCase();
        return ua.contains("bot");
    }
}
