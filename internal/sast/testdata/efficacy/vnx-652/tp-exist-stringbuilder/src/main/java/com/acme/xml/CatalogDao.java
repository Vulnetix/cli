package com.acme.xml;

import org.xmldb.api.base.ResourceSet;
import org.xmldb.api.modules.XQueryService;

public class CatalogDao {
    public ResourceSet lookup(XQueryService service, String category) throws Exception {
        StringBuilder sb = new StringBuilder("for $p in collection('/db/catalog')//product");
        sb.append(" where $p/category = '").append(category).append("' return $p");
~>        return service.query(sb.toString());
    }
}
