package com.acme;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

@Component
@Scope("prototype")
public class Wizard {
    private int step;

    public void next() {
        step++;
    }
}
