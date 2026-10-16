package com.acme;
public class Doc {
    // never do new IvParameterSpec("0000000000000000".getBytes())
    String s = "new IvParameterSpec(new byte[16])";
}
