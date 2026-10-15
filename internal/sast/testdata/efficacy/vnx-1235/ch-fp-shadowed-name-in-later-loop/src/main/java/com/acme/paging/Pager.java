package com.acme.paging;

public class Pager {

    Integer firstPage() {
        Integer page = 0;
        return page;
    }

    void walk(Client client, int pages) {
        for (int page = 0; page < pages; page++) {
            client.fetch(page);
        }
    }

    long sum(long[] values) {
        long acc = 0;
        int n = 0;
        while (n < values.length) {
            acc += values[n];
            n++;
        }
        return acc;
    }
}
