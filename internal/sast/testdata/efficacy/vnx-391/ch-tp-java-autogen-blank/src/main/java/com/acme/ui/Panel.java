package com.acme.ui;

public class Panel {
    public void render(Canvas c) {
        try {
            c.paint(this);
~>        } catch (RenderException e) {
            // TODO Auto-generated catch block
        }
    }

    public String title(Model m) {
        try {
            return m.title();
~>        } catch (IllegalStateException ex) {
            ex.getMessage();
        }
        return "";
    }
}
