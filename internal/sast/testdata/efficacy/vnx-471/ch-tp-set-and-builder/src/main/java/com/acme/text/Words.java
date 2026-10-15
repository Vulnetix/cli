package com.acme.text;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Words {
~>    public static final Set<String> STOP_WORDS = new HashSet<>(Arrays.asList("a", "an", "the"));
~>    public static final StringBuilder SHARED = new StringBuilder();
~>    public static final byte[] MAGIC = new byte[] { 0x50, 0x4b };
}
