package com.acme.kiosk;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class PinPad extends JPanel {

    private final JPasswordField pinField = new JPasswordField(6);
    private final CardTerminal terminal;

    public PinPad(CardTerminal terminal) {
        this.terminal = terminal;
        JButton enter = new JButton("Enter");
        enter.addActionListener(e -> submit());
        add(pinField);
        add(enter);
    }

    private void submit() {
~>        String pin = pinField.getText();
        terminal.verifyPin(pin);
        pinField.setText("");
    }
}
