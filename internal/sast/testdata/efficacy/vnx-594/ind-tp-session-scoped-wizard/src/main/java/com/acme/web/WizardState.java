package com.acme.web;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Named;
import java.util.ArrayList;
import java.util.List;

@Named("wizard")
@SessionScoped
~>public class WizardState {

    private int step = 1;
    private final List<String> answers = new ArrayList<>();

    public int getStep() {
        return step;
    }

    public void next(String answer) {
        answers.add(answer);
        step++;
    }
}
