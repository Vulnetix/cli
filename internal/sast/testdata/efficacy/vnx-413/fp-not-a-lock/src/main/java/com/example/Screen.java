package com.example;

public class Screen {
    private final Editor editor = new Editor();
    private final Database db = new Database();

    public void freeze() {
        editor.lock();
        db.lock();
        synchronized (editor) {
            editor.refresh();
        }
    }
}
