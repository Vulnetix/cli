package com.acme.paging;

public class PageMath {

    public boolean isLastPage(int page, int totalPages) {
        return page == totalPages;
    }

    public boolean isEmpty(Integer count) {
        return count == 0;
    }

    public boolean atLimit(Long used, long limit) {
        return used == limit;
    }

    public boolean sameChar(char a, char b) {
        return a == b;
    }
}
