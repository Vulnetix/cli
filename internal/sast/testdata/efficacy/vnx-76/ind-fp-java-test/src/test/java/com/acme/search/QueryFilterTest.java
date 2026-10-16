package com.acme.search;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class QueryFilterTest {

    @Test
    void stripsKeyword() {
        String raw = "1 SELECT 2";
        String expected = raw.replace("SELECT", "");
        assertEquals(expected, QueryFilter.clean(raw));
    }
}
