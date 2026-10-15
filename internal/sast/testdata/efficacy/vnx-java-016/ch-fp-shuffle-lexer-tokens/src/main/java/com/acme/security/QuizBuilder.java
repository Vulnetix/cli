package com.acme.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class QuizBuilder {
    private final Random random = new Random();

    public List<String> shuffledTokens(List<String> tokens) {
        List<String> copy = new ArrayList<>(tokens);
        Collections.shuffle(copy, random);
        return copy;
    }

    public String pickToken(List<String> tokens) {
        return tokens.get(random.nextInt(tokens.size()));
    }
}
