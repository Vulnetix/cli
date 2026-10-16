package com.acme;
import javax.crypto.spec.IvParameterSpec;
public class Cbc {
    IvParameterSpec iv() {
~>        return new IvParameterSpec("1234567890123456".getBytes());
    }
}
