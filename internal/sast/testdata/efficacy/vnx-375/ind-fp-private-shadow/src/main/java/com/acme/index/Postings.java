package com.acme.index;

import java.util.ArrayList;
import java.util.List;

public class Postings {
    private final List<Integer> docs = new ArrayList<>();

    private List<Integer> rawDocs() {
        return docs;
    }

    List<Integer> docsForMerge() {
        return docs;
    }

    public List<Integer> snapshot() {
        List<Integer> docs = new ArrayList<>(this.docs);
        docs.sort(null);
        return docs;
    }
}
