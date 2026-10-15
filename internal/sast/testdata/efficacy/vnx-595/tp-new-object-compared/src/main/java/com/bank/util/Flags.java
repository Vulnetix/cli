package com.bank.util;

public class Flags {
    boolean isDefault(Object value) {
~>        if (value == new Integer(0)) {
            return true;
        }
~>        return new Long(7L) != value;
    }
}
