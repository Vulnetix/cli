package com.acme.text;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import com.google.common.collect.ImmutableList;

public class Words {
    public static final List<String> STOP_WORDS = List.of("a", "an", "the");
    public static final Set<String> FLAGS = Collections.unmodifiableSet(new java.util.HashSet<>(Arrays.asList("x", "y")));
    public static final ImmutableList<String> TAGS = ImmutableList.of("alpha", "beta");
    public static final Map<String, Integer> CODES = Map.of("ok", 200);
}
