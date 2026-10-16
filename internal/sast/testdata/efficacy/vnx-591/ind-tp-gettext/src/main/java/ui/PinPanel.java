package ui;

import javax.swing.JPasswordField;

public class PinPanel {
    private JPasswordField pinField;

    String currentPin() {
~>        String pin = pinField.getText();
        return pin.trim();
    }
}
