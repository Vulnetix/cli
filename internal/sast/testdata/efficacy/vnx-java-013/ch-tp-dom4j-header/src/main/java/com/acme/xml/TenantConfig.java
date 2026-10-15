package com.acme.xml;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.Node;

public class TenantConfig {
    private final Document config;

    public TenantConfig(Document config) {
        this.config = config;
    }

    public List<Node> settings(HttpServletRequest request) {
        String tenant = request.getHeader("X-Tenant");
~>        return config.selectNodes("//tenant[@id='" + tenant + "']/setting");
    }
}
