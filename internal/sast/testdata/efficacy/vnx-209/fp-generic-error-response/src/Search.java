package com.shop;

import java.sql.SQLException;

public class Search {
    public Result find(String name) {
        try {
            return Result.ok(dao.find(name));
        } catch (SQLException sqle) {
            log.warn("search failed: {}", sqle.getMessage());
            return Result.failed().output("search failed").build();
        } catch (IllegalArgumentException e) {
            return Result.failed().output(e.getMessage()).build();
        }
    }
}
