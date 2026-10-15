package com.shop.api;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.QueryParam;
import org.springframework.web.bind.annotation.RequestParam;

public class CatalogResource {

    public Page list(@QueryParam("page") int page, @RequestParam(defaultValue = "20") int size) {
        return repo.page(page, size);
    }

    public Item item(HttpServletRequest request) {
        try {
            long id = Long.parseLong(request.getParameter("id"));
            return repo.item(id);
        } catch (IllegalStateException | NumberFormatException e) {
            throw new BadRequest("id must be a number");
        }
    }

    public int pageSize() {
        return Integer.parseInt(System.getProperty("catalog.pageSize", "20"));
    }
}
