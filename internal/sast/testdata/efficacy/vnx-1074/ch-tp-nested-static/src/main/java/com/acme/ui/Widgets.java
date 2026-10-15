package com.acme.ui;

public final class Widgets {
    public static class W1 extends javax.swing.JPanel {
    }

    public static class W2 extends W1 {
    }

    public static class W3 extends W2 {
    }

    public static class W4 extends W3 {
    }

    public static class W5 extends W4 {
    }

    public static class W6 extends W5 {
    }

~>    public static class W7 extends Widgets.W6 {
    }
}
