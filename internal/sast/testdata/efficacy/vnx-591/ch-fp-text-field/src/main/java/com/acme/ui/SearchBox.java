package com.acme.ui;

import javax.swing.JTextField;

public class SearchBox {
    private final JTextField query = new JTextField(30);

    String text() {
        String q = query.getText();
        return q.trim();
    }
}
