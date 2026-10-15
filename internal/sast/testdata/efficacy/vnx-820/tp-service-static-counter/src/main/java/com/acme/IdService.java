package com.acme;

import org.springframework.stereotype.Service;

@Service
public class IdService {
    private static int next = 0;

    public int nextId() {
~>        return next++;
    }
}
