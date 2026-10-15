package com.acme.model;

import java.io.Serializable;

~>public class Order implements Serializable {
    private String id;

    public static class Line implements Serializable {
        private static final long serialVersionUID = 7L;
        private String sku;
    }

~>    private static final class Note implements Serializable {
        private String text;
    }
}
