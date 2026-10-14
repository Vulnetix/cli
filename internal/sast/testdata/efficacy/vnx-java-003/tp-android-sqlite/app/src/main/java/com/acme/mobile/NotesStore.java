package com.acme.mobile;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

public class NotesStore {
    private SQLiteDatabase db;

    public Cursor byTitle(String title) {
~>        return db.rawQuery("SELECT * FROM notes WHERE title = '" + title + "'", null);
    }

    public void remove(String id) {
~>        db.execSQL("DELETE FROM notes WHERE _id = " + id);
    }
}
